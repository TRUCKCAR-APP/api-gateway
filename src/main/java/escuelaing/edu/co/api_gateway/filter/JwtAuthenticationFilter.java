package escuelaing.edu.co.api_gateway.filter;

import escuelaing.edu.co.api_gateway.error.GatewayErrors;
import escuelaing.edu.co.api_gateway.telemetry.WsTicketStore;
import escuelaing.edu.co.api_gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /** Telemetría GPS en tiempo real (STOMP sobre WebSocket hacia fleets-drivers). */
    private static final String WS_TELEMETRY_PATH = "/ws-telemetry";
    /** Ticket de un solo uso (POST /api/v1/telemetry/ws-ticket): el navegador no puede enviar cabeceras al abrir un WebSocket. */
    private static final String TICKET_PARAM = "ticket";
    /** Ya no autentica: si un cliente antiguo lo envía, se quita de la URL para que no llegue a fleets-drivers. */
    private static final String LEGACY_TOKEN_PARAM = "access_token";
    /** Un X-Correlation-Id del cliente se propaga solo si es corto y sin caracteres de control (logs, cabeceras). */
    private static final int MAX_CORRELATION_ID_LENGTH = 128;

    private final JwtUtil jwtUtil;
    private final WsTicketStore tickets;

    /**
     * Rutas sin JWT. Del actuator solo /actuator/health (y sus probes /actuator/health/**): el resto, en especial
     * /actuator/gateway, permitiría listar o registrar rutas hacia los servicios internos.
     */
    private final List<String> openEndpoints = List.of(
            "/api/v1/auth",
            "/actuator/health"
    );

    /**
     * Seguimiento público de envíos (enlace firmado que valida Load-Allocation): sin JWT, solo GET y sin "..", "%2e" ni
     * "%2f", para que el prefijo abierto no sirva de puente hacia otras rutas de /api/v1/loads tras normalizar.
     */
    private static final String PUBLIC_TRACKING_PREFIX = "/api/v1/loads/public-tracking/";

    /**
     * Rutas solo para ADMIN. El servicio también lo exige (@PreAuthorize en Notifications); el gateway responde 403 antes
     * de reenviar para que un token de otro rol ni siquiera llegue al servicio.
     */
    private static final List<String> ADMIN_ONLY_PREFIXES = List.of("/api/v1/templates");

    public JwtAuthenticationFilter(JwtUtil jwtUtil, WsTicketStore tickets) {
        this.jwtUtil = jwtUtil;
        this.tickets = tickets;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        String correlationId = correlationIdOf(request);
        exchange.getResponse().getHeaders().set("X-Correlation-Id", correlationId);

        boolean isOpen = openEndpoints.stream()
                .anyMatch(endpoint -> path.equals(endpoint) || path.startsWith(endpoint + "/"))
                || isPublicTracking(request, path);
        if (isOpen) {
            return forwardWithCorrelationId(exchange, chain, correlationId);
        }

        boolean telemetrySocket = path.equals(WS_TELEMETRY_PATH) || path.startsWith(WS_TELEMETRY_PATH + "/");
        String token = bearerToken(request);
        if (token != null) {
            Optional<Claims> claims = jwtUtil.validClaims(token);
            if (claims.isEmpty()) {
                return unauthorized(exchange, "El token de acceso no es válido o ya venció; inicie sesión de nuevo");
            }
            if (adminOnly(path) && !"ADMIN".equals(roleOf(claims.get()))) {
                return forbidden(exchange);
            }
            return forwardAuthenticated(exchange, chain, claims.get().getSubject(), roleOf(claims.get()), correlationId,
                    telemetrySocket);
        }
        if (telemetrySocket) {
            // Navegador: identidad del ticket de un solo uso. Sin ticket, vencido o ya usado: 401.
            String ticket = request.getQueryParams().getFirst(TICKET_PARAM);
            if (ticket == null || ticket.isBlank()) {
                return unauthorized(exchange, "El WebSocket de telemetría requiere un ticket (POST /api/v1/telemetry/ws-ticket)");
            }
            // Se decide antes de reenviar: el reenvío también termina vacío (Mono<Void>) y no debe confundirse con
            // "ticket inexistente".
            return tickets.redeem(ticket)
                    .map(Optional::of)
                    .defaultIfEmpty(Optional.empty())
                    // Solo los errores del canje (Redis): los del reenvío posterior siguen su curso.
                    .onErrorMap(e -> {
                        log.warn("No se pudo canjear el ticket del WebSocket: {}", e.getMessage());
                        return new TicketStoreDown();
                    })
                    .flatMap(owner -> owner
                            .map(o -> forwardAuthenticated(exchange, chain, o.userId(), o.role(), correlationId, true))
                            .orElseGet(() -> unauthorized(exchange, "El ticket del WebSocket no es válido, ya se usó o venció")))
                    .onErrorResume(TicketStoreDown.class, e -> GatewayErrors.write(exchange,
                            HttpStatus.SERVICE_UNAVAILABLE, "Servicio no disponible",
                            "No se pudo validar el ticket del WebSocket; intente de nuevo en unos segundos"));
        }
        return unauthorized(exchange, "Se requiere autenticación: envíe el token en la cabecera Authorization: Bearer <token>");
    }

    /** Fallo de Redis al canjear el ticket: 503 (no es culpa del cliente ni un ticket inválido). */
    private static final class TicketStoreDown extends RuntimeException {
        TicketStoreDown() {
            super(null, null, false, false);
        }
    }

    private Mono<Void> forwardAuthenticated(ServerWebExchange exchange, GatewayFilterChain chain, String userId,
                                            String role, String correlationId, boolean telemetrySocket) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpRequest.Builder requestBuilder = request.mutate();
        if (telemetrySocket) {
            // Ninguna credencial viaja al servicio en la URL.
            requestBuilder.uri(UriComponentsBuilder.fromUri(request.getURI())
                    .replaceQueryParam(TICKET_PARAM)
                    .replaceQueryParam(LEGACY_TOKEN_PARAM)
                    .build(true)
                    .toUri());
        }
        ServerHttpRequest mutatedRequest = requestBuilder
                .headers(requestHeaders -> {
                    requestHeaders.remove("X-Auth-User");
                    requestHeaders.remove("X-Auth-Role");
                    requestHeaders.remove("X-Correlation-Id");
                })
                .header("X-Auth-User", userId)
                .header("X-Auth-Role", role)
                .header("X-Correlation-Id", correlationId)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private static boolean adminOnly(String path) {
        return ADMIN_ONLY_PREFIXES.stream().anyMatch(prefix -> path.equals(prefix) || path.startsWith(prefix + "/"));
    }

    /** Ruta reservada a ADMIN con un token válido de otro rol: 403 con el JSON normalizado (X-Correlation-Id ya fijado). */
    private static Mono<Void> forbidden(ServerWebExchange exchange) {
        return GatewayErrors.write(exchange, HttpStatus.FORBIDDEN, "Acceso denegado",
                "Esta ruta solo está disponible para administradores");
    }

    private static Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        return GatewayErrors.write(exchange, HttpStatus.UNAUTHORIZED, "No autenticado", message);
    }

    /** JWT de la cabecera Authorization. Un token en la URL nunca autentica, tampoco en /ws-telemetry. */
    private static String bearerToken(ServerHttpRequest request) {
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = authHeader.substring(7).trim();
        // "Bearer " vacío cuenta como token presente e inválido: el cliente intentó autenticarse.
        return token;
    }

    /** Rol emitido por User-Identity (CONDUCTOR, COORDINADOR, GENERADOR, ADMIN); JwtUtil ya exigió que exista. */
    private String roleOf(Claims claims) {
        Object role = claims.get("role");
        return role == null ? "" : role.toString();
    }

    private static String correlationIdOf(ServerHttpRequest request) {
        String incoming = request.getHeaders().getFirst("X-Correlation-Id");
        boolean usable = incoming != null && !incoming.isBlank() && incoming.length() <= MAX_CORRELATION_ID_LENGTH
                && incoming.chars().allMatch(c -> c >= 0x21 && c <= 0x7e);
        return usable ? incoming : UUID.randomUUID().toString();
    }

    private static boolean isPublicTracking(ServerHttpRequest request, String path) {
        String lower = path.toLowerCase();
        return HttpMethod.GET.equals(request.getMethod())
                && path.startsWith(PUBLIC_TRACKING_PREFIX)
                && path.length() > PUBLIC_TRACKING_PREFIX.length()
                && !path.contains("..") && !lower.contains("%2e") && !lower.contains("%2f");
    }

    private Mono<Void> forwardWithCorrelationId(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            String correlationId) {
        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove("X-Correlation-Id");
                    headers.remove("X-Auth-User");
                    headers.remove("X-Auth-Role");
                })
                .header("X-Correlation-Id", correlationId)
                .build();
        return chain.filter(exchange.mutate().request(request).build());
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
