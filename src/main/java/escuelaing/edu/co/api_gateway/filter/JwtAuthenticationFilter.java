package escuelaing.edu.co.api_gateway.filter;

import escuelaing.edu.co.api_gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    private final List<String> openEndpoints = List.of(
            "/api/v1/auth",
            "/actuator",
            "/v3/api-docs",
            "/swagger-ui"
    );

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
                .anyMatch(endpoint -> path.equals(endpoint) || path.startsWith(endpoint + "/"));
        if (isOpen) {
            return forwardWithCorrelationId(exchange, chain, correlationId);
        }

        HttpHeaders headers = request.getHeaders();
        if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        if (!jwtUtil.isTokenValid(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        Claims claims = jwtUtil.getClaims(token);
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(requestHeaders -> {
                    requestHeaders.remove("X-Auth-User");
                    requestHeaders.remove("X-Correlation-Id");
                })
                .header("X-Auth-User", claims.getSubject())
                .header("X-Correlation-Id", correlationId)
                .build();

        exchange.getResponse().getHeaders().set("X-Correlation-Id", correlationId);
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private Mono<Void> forwardWithCorrelationId(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            String correlationId) {
        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove("X-Correlation-Id");
                    headers.remove("X-Auth-User");
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