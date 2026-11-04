package escuelaing.edu.co.api_gateway.filter;

import escuelaing.edu.co.api_gateway.telemetry.WsTicketStore;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private static final String TEST_SECRET = "dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=";
    private final JwtUtil jwtUtil = new JwtUtil(TEST_SECRET);
    private final WsTicketStore tickets = mock(WsTicketStore.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil, tickets);

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
    void onlyActuatorHealthIsPublic() {
        for (String path : new String[] {"/actuator/gateway/routes", "/actuator/info", "/actuator", "/v3/api-docs"}) {
            MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(path).build());

            filter.filter(exchange, mock(GatewayFilterChain.class)).block();

            assertThat(exchange.getResponse().getStatusCode()).as(path).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
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
    void publicTrackingIsAnonymousOnlyForGetAndNeverForwardsIdentity() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/loads/public-tracking/abc.def")
                        .header("X-Auth-User", "spoofed")
                        .header("X-Auth-Role", "ADMIN")
                        .build());
        boolean[] forwarded = {false};
        GatewayFilterChain chain = forwardedExchange -> {
            forwarded[0] = true;
            assertThat(forwardedExchange.getRequest().getHeaders().containsKey("X-Auth-User")).isFalse();
            assertThat(forwardedExchange.getRequest().getHeaders().containsKey("X-Auth-Role")).isFalse();
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertThat(forwarded[0]).isTrue();
    }

    @Test
    void publicTrackingPrefixCannotReachOtherLoadRoutes() {
        for (String path : new String[] {"/api/v1/loads/public-tracking/../5", "/api/v1/loads/public-tracking/%2e%2e/5",
                "/api/v1/loads/public-tracking/x%2F..%2F5", "/api/v1/loads/public-tracking/", "/api/v1/loads/5/public-tracking-link"}) {
            MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(path).build());

            filter.filter(exchange, mock(GatewayFilterChain.class)).block();

            assertThat(exchange.getResponse().getStatusCode()).as(path).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
        MockServerWebExchange post = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/loads/public-tracking/abc").build());
        filter.filter(post, mock(GatewayFilterChain.class)).block();
        assertThat(post.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
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

    @Test
    void propagatesGeneradorRoleAndDropsSpoofedControlTowerRole() {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
        String token = Jwts.builder()
                .subject("generator-1")
                .claim("role", "GENERADOR")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key)
                .compact();

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/loads")
                        .header("Authorization", "Bearer " + token)
                        .header("X-Auth-Role", "COORDINADOR")
                        .header("X-Auth-User", "otro-usuario")
                        .build());
        GatewayFilterChain chain = forwardedExchange -> {
            assertThat(forwardedExchange.getRequest().getHeaders().get("X-Auth-Role")).containsExactly("GENERADOR");
            assertThat(forwardedExchange.getRequest().getHeaders().get("X-Auth-User")).containsExactly("generator-1");
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();
    }

    private String tokenFor(String subject, String role) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
        return Jwts.builder()
                .subject(subject)
                .claim("role", role)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key)
                .compact();
    }

    private static final String TICKET = "3f2b8c1e-6d4a-4f7e-9b1c-2a5d8e7f9c01";

    @Test
    void telemetryHandshakeRedeemsTheTicketAndStripsItBeforeForwarding() {
        when(tickets.redeem(TICKET)).thenReturn(Mono.just(new WsTicketStore.TicketOwner("driver-1", "CONDUCTOR")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/ws-telemetry?ticket=" + TICKET + "&v=1")
                        .header("Upgrade", "websocket")
                        .header("X-Auth-User", "intruso")
                        .build());
        GatewayFilterChain chain = forwardedExchange -> {
            var forwarded = forwardedExchange.getRequest();
            assertThat(forwarded.getHeaders().get("X-Auth-User")).containsExactly("driver-1");
            assertThat(forwarded.getHeaders().get("X-Auth-Role")).containsExactly("CONDUCTOR");
            assertThat(forwarded.getURI().getQuery()).isEqualTo("v=1");
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        verify(tickets).redeem(TICKET);
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aJwtInTheUrlNoLongerOpensTheTelemetrySocket() {
        when(tickets.redeem(any())).thenReturn(Mono.empty());
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/ws-telemetry?access_token=" + tokenFor("driver-1", "CONDUCTOR"))
                        .header("Upgrade", "websocket").build());

        filter.filter(exchange, forwardedExchange -> Mono.error(new AssertionError("no debe reenviarse"))).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anUnknownExpiredOrAlreadyUsedTicketIsRejected() {
        when(tickets.redeem(any())).thenReturn(Mono.empty());
        for (String uri : new String[]{"/ws-telemetry", "/ws-telemetry?ticket=" + TICKET, "/ws-telemetry?ticket=otro"}) {
            MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(uri).build());
            filter.filter(exchange, forwardedExchange -> Mono.error(new AssertionError("no debe reenviarse"))).block();
            assertThat(exchange.getResponse().getStatusCode()).as(uri).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Test
    void clientsThatCanSendHeadersStillOpenTheSocketWithAuthorization() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/ws-telemetry?access_token=sobrante")
                        .header("Authorization", "Bearer " + tokenFor("coord-1", "COORDINADOR"))
                        .build());
        GatewayFilterChain chain = forwardedExchange -> {
            var forwarded = forwardedExchange.getRequest();
            assertThat(forwarded.getHeaders().get("X-Auth-User")).containsExactly("coord-1");
            assertThat(forwarded.getQueryParams()).doesNotContainKey("access_token");
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        verify(tickets, never()).redeem(any());
    }

    @Test
    void anInvalidBearerOnTheSocketIsRejectedWithoutLookingForATicket() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/ws-telemetry?ticket=" + TICKET).header("Authorization", "Bearer basura").build());

        filter.filter(exchange, forwardedExchange -> Mono.error(new AssertionError("no debe reenviarse"))).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(tickets, never()).redeem(any());
    }

    @Test
    void queryTokenIsIgnoredOutsideTheTelemetrySocket() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/loads?access_token=" + tokenFor("coord-1", "COORDINADOR")).build());

        filter.filter(exchange, forwardedExchange -> Mono.error(new AssertionError("no debe reenviarse"))).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
