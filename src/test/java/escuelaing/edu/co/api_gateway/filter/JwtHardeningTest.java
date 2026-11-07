package escuelaing.edu.co.api_gateway.filter;

import escuelaing.edu.co.api_gateway.telemetry.WsTicketStore;
import escuelaing.edu.co.api_gateway.util.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Validación estricta del JWT, errores normalizados (401/503 con JSON) y canje del ticket del WebSocket. */
class JwtHardeningTest {

    private static final String TEST_SECRET = "dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=";
    private static final SecretKey KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
    private static final String TICKET = "3f2b8c1e-6d4a-4f7e-9b1c-2a5d8e7f9c01";

    private final WsTicketStore tickets = mock(WsTicketStore.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(new JwtUtil(TEST_SECRET), tickets);

    private static String token(String subject, Object role, boolean withExpiration) {
        var builder = Jwts.builder();
        if (subject != null) {
            builder.subject(subject);
        }
        if (role != null) {
            builder.claim("role", role);
        }
        if (withExpiration) {
            builder.expiration(new Date(System.currentTimeMillis() + 60_000));
        }
        return builder.signWith(KEY).compact();
    }

    private MockServerWebExchange call(String path, String token) {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get(path);
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        MockServerWebExchange exchange = MockServerWebExchange.from(request.build());
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.empty());
        filter.filter(exchange, chain).block();
        return exchange;
    }

    @Test
    void missingTokenIsA401WithAClearJsonMessage() {
        MockServerWebExchange exchange = call("/api/v1/loads", null);

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Bearer");
        String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body).contains("\"status\":401", "\"error\":\"No autenticado\"", "Authorization: Bearer",
                "\"path\":\"/api/v1/loads\"", "\"correlationId\"");
    }

    @Test
    void tokensWithoutSubjectExpirationOrAKnownUserRoleAreRejected() {
        String[] invalid = {
                token(null, "CONDUCTOR", true),          // sin sub: X-Auth-User vacío (antes, 500)
                token("  ", "CONDUCTOR", true),
                token("driver-1", null, true),           // sin rol
                token("driver-1", "SYSTEM", true),       // rol interno: nunca desde fuera
                token("driver-1", "SUPERADMIN", true),
                token("driver-1", "CONDUCTOR", false),   // sin exp: no caducaría nunca
                "no.es.un.jwt",
                ""
        };
        for (String token : invalid) {
            MockServerWebExchange exchange = call("/api/v1/loads", token);
            assertThat(exchange.getResponse().getStatusCode()).as(token).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(exchange.getResponse().getBodyAsString().block()).as(token).contains("no es válido o ya venció");
        }
    }

    @Test
    void validUserTokenStillPasses() {
        MockServerWebExchange exchange = call("/api/v1/loads", token("coord-1", "COORDINADOR", true));

        assertThat(exchange.getResponse().getStatusCode()).isNull(); // lo decide el servicio, no el gateway
    }

    @Test
    void oversizedOrHostileCorrelationIdIsReplaced() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/auth/login")
                .header("X-Correlation-Id", "x".repeat(500)).build());
        GatewayFilterChain chain = forwarded -> Mono.empty();

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getHeaders().getFirst("X-Correlation-Id")).hasSizeLessThan(100);
    }

    @Test
    void telemetrySocketWithoutTicketIs401AndNeverQueriesRedis() {
        MockServerWebExchange exchange = call("/ws-telemetry", null);

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getBodyAsString().block()).contains("requiere un ticket");
        verifyNoInteractions(tickets);
    }

    @Test
    void usedOrExpiredTicketIs401() {
        when(tickets.redeem(TICKET)).thenReturn(Mono.empty());

        MockServerWebExchange exchange = call("/ws-telemetry?ticket=" + TICKET, null);

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getBodyAsString().block()).contains("ya se usó o venció");
    }

    @Test
    void redisDownWhileRedeemingIs503NotA500() {
        when(tickets.redeem(anyString())).thenReturn(Mono.error(new IllegalStateException("Redis caído")));

        MockServerWebExchange exchange = call("/ws-telemetry?ticket=" + TICKET, null);

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(exchange.getResponse().getBodyAsString().block()).contains("ticket del WebSocket");
    }

    @Test
    void invalidBearerOnTheSocketIsRejectedWithoutTryingTheTicket() {
        MockServerWebExchange exchange = call("/ws-telemetry?ticket=" + TICKET, "basura");

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(tickets, never()).redeem(anyString());
    }
}
