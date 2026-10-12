package escuelaing.edu.co.api_gateway.filter;

import escuelaing.edu.co.api_gateway.util.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class JwtAuthenticationFilterTest {

    private static final String TEST_SECRET = "dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=";
    private final JwtUtil jwtUtil = new JwtUtil(TEST_SECRET);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil);

    @Test
    void generatesAndPropagatesCorrelationIdForPublicEndpoint() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/auth/login").build());
        GatewayFilterChain chain = forwardedExchange -> {
            assertThat(forwardedExchange.getRequest().getHeaders().getFirst("X-Correlation-Id"))
                    .isNotBlank();
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getHeaders().getFirst("X-Correlation-Id"))
                .isNotBlank();
    }

    @Test
    void preservesCorrelationIdForPublicEndpoint() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/actuator/health")
                        .header("X-Correlation-Id", "correlation-123")
                        .build());
        GatewayFilterChain chain = forwardedExchange -> {
            assertThat(forwardedExchange.getRequest().getHeaders().getFirst("X-Correlation-Id"))
                    .isEqualTo("correlation-123");
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getHeaders().getFirst("X-Correlation-Id"))
                .isEqualTo("correlation-123");
    }

    @Test
    void rejectsProtectedEndpointWithoutBearerToken() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/loads").build());
        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void propagatesIdentityAndCorrelationIdForValidToken() {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
        String token = Jwts.builder()
                .subject("user-123")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key)
                .compact();

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/loads")
                        .header("Authorization", "Bearer " + token)
                        .header("X-Auth-User", "spoofed-user")
                        .header("X-Correlation-Id", "correlation-456")
                        .build());
        GatewayFilterChain chain = forwardedExchange -> {
            assertThat(forwardedExchange.getRequest().getHeaders().getFirst("X-Auth-User"))
                    .isEqualTo("user-123");
            assertThat(forwardedExchange.getRequest().getHeaders().getFirst("X-Correlation-Id"))
                    .isEqualTo("correlation-456");
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getHeaders().getFirst("X-Correlation-Id"))
                .isEqualTo("correlation-456");
    }

    @Test
    void propagatesRoleFromTokenAndDropsSpoofedRoleHeader() {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
        String token = Jwts.builder()
                .subject("driver-1")
                .claim("role", "CONDUCTOR")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key)
                .compact();

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.patch("/api/v1/loads/1/cancel")
                        .header("Authorization", "Bearer " + token)
                        .header("X-Auth-Role", "ADMIN")
                        .build());
        GatewayFilterChain chain = forwardedExchange -> {
            assertThat(forwardedExchange.getRequest().getHeaders().get("X-Auth-Role"))
                    .containsExactly("CONDUCTOR");
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();
    }

    @Test
    void publicEndpointsNeverForwardClientSuppliedIdentityHeaders() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/auth/login")
                        .header("X-Auth-User", "spoofed")
                        .header("X-Auth-Role", "ADMIN")
                        .build());
        GatewayFilterChain chain = forwardedExchange -> {
            assertThat(forwardedExchange.getRequest().getHeaders().containsKey("X-Auth-User")).isFalse();
            assertThat(forwardedExchange.getRequest().getHeaders().containsKey("X-Auth-Role")).isFalse();
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();
    }
}
