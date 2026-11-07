package escuelaing.edu.co.api_gateway.filter;

import escuelaing.edu.co.api_gateway.telemetry.WsTicketStore;
import escuelaing.edu.co.api_gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
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

    /** Telemetría GPS en tiempo real (STOMP sobre WebSocket hacia fleets-drivers). */
    private static final String WS_TELEMETRY_PATH = "/ws-telemetry";
    /** Ticket de un solo uso (POST /api/v1/telemetry/ws-ticket): el navegador no puede enviar cabeceras al abrir un WebSocket. */
    private static final String TICKET_PARAM = "ticket";
    /** Ya no autentica: si un cliente antiguo lo envía, se quita de la URL para que no llegue a fleets-drivers. */
    private static final String LEGACY_TOKEN_PARAM = "access_token";

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
        String incomingCorrelationId = request.getHeaders().getFirst("X-Correlation-Id");
        String correlationId = incomingCorrelationId == null || incomingCorrelationId.isBlank()
                ? UUID.randomUUID().toString()
                : incomingCorrelationId;

        boolean isOpen = openEndpoints.stream()
                .anyMatch(endpoint -> path.equals(endpoint) || path.startsWith(endpoint + "/"))
                || isPublicTracking(request, path);
        if (isOpen) {
            return forwardWithCorrelationId(exchange, chain, correlationId);
        }

        boolean telemetrySocket = path.equals(WS_TELEMETRY_PATH) || path.startsWith(WS_TELEMETRY_PATH + "/");
        String token = bearerToken(request);
        if (token != null && jwtUtil.isTokenValid(token)) {
            Claims claims = jwtUtil.getClaims(token);
            if (adminOnly(path) && !"ADMIN".equals(roleOf(claims))) {
                return forbidden(exchange, correlationId);
            }
            return forwardAuthenticated(exchange, chain, claims.getSubject(), roleOf(claims), correlationId,
                    telemetrySocket);
        }
        if (token == null && telemetrySocket) {
            // Navegador: identidad del ticket de un solo uso. Sin ticket, vencido o ya usado: 401.
            String ticket = request.getQueryParams().getFirst(TICKET_PARAM);
            // Se decide antes de reenviar: el reenvío también termina vacío (Mono<Void>) y no debe confundirse con
            // "ticket inexistente".
            return tickets.redeem(ticket)
                    .map(Optional::of)
                    .defaultIfEmpty(Optional.empty())
                    .flatMap(owner -> owner
                            .map(o -> forwardAuthenticated(exchange, chain, o.userId(), o.role(), correlationId, true))
                            .orElseGet(() -> unauthorized(exchange)));
        }
        return unauthorized(exchange);
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

        exchange.getResponse().getHeaders().set("X-Correlation-Id", correlationId);
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private static boolean adminOnly(String path) {
        return ADMIN_ONLY_PREFIXES.stream().anyMatch(prefix -> path.equals(prefix) || path.startsWith(prefix + "/"));
    }

    private static Mono<Void> forbidden(ServerWebExchange exchange, String correlationId) {
        exchange.getResponse().getHeaders().set("X-Correlation-Id", correlationId);
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    private static Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    /** JWT de la cabecera Authorization. Un token en la URL nunca autentica, tampoco en /ws-telemetry. */
    private static String bearerToken(ServerHttpRequest request) {
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return authHeader != null && authHeader.startsWith("Bearer ") ? authHeader.substring(7) : null;
    }

    /** Rol emitido por User-Identity (CONDUCTOR, COORDINADOR, GENERADOR, ADMIN); vacío si el token no lo trae. */
    private String roleOf(Claims claims) {
        Object role = claims.get("role");
        return role == null ? "" : role.toString();
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
        exchange.getResponse().getHeaders().set("X-Correlation-Id", correlationId);
        return chain.filter(exchange.mutate().request(request).build());
    }

    @Override
    public int getOrder() {
        return -1;
    }
}