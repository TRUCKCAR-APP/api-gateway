package escuelaing.edu.co.api_gateway.filter;

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
import java.util.UUID;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    /** Telemetría GPS en tiempo real (STOMP sobre WebSocket hacia fleets-drivers). */
    private static final String WS_TELEMETRY_PATH = "/ws-telemetry";
    private static final String ACCESS_TOKEN_PARAM = "access_token";

    private final JwtUtil jwtUtil;

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

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        String correlationId = request.getHeaders().getFirst("X-Correlation-Id");
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }

        boolean isOpen = openEndpoints.stream()
                .anyMatch(endpoint -> path.equals(endpoint) || path.startsWith(endpoint + "/"))
                || isPublicTracking(request, path);
        if (isOpen) {
            return forwardWithCorrelationId(exchange, chain, correlationId);
        }

        boolean telemetrySocket = path.equals(WS_TELEMETRY_PATH) || path.startsWith(WS_TELEMETRY_PATH + "/");
        String token = extractToken(request, telemetrySocket);
        if (token == null || !jwtUtil.isTokenValid(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        Claims claims = jwtUtil.getClaims(token);
        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();
        if (telemetrySocket) {
            // El token no viaja al servicio: se quita de la URL tras validarlo.
            requestBuilder.uri(UriComponentsBuilder.fromUri(request.getURI())
                    .replaceQueryParam(ACCESS_TOKEN_PARAM)
                    .build(true)
                    .toUri());
        }
        ServerHttpRequest mutatedRequest = requestBuilder
                .headers(requestHeaders -> {
                    requestHeaders.remove("X-Auth-User");
                    requestHeaders.remove("X-Auth-Role");
                    requestHeaders.remove("X-Correlation-Id");
                })
                .header("X-Auth-User", claims.getSubject())
                .header("X-Auth-Role", roleOf(claims))
                .header("X-Correlation-Id", correlationId)
                .build();

        exchange.getResponse().getHeaders().set("X-Correlation-Id", correlationId);
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    /**
     * JWT de la cabecera Authorization. En el handshake de /ws-telemetry también se acepta ?access_token=..., porque
     * la API WebSocket del navegador no permite enviar cabeceras; en cualquier otra ruta el token en la URL se ignora.
     */
    private String extractToken(ServerHttpRequest request, boolean telemetrySocket) {
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        if (telemetrySocket) {
            String queryToken = request.getQueryParams().getFirst(ACCESS_TOKEN_PARAM);
            return queryToken == null || queryToken.isBlank() ? null : queryToken;
        }
        return null;
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