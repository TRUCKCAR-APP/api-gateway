package escuelaing.edu.co.api_gateway.telemetry;

import escuelaing.edu.co.api_gateway.util.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class WsTicketControllerTest {

    private static final String TEST_SECRET = "dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=";
    private final WsTicketStore tickets = mock(WsTicketStore.class);
    private final WsTicketController controller = new WsTicketController(new JwtUtil(TEST_SECRET), tickets);

    private static org.springframework.web.server.ServerWebExchange exchange() {
        return org.springframework.mock.web.server.MockServerWebExchange.from(
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.post("/api/v1/telemetry/ws-ticket").build());
    }

    private static String token(String subject, String role) {
        return Jwts.builder().subject(subject).claim("role", role)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET)))
                .compact();
    }

    @Test
    void aValidJwtGetsATicketThatIsNeverCached() {
        when(tickets.issue("driver-1", "CONDUCTOR")).thenReturn(Mono.just("ticket-1"));
        when(tickets.ttl()).thenReturn(Duration.ofSeconds(30));

        ResponseEntity<Map<String, Object>> response =
                controller.issue("Bearer " + token("driver-1", "CONDUCTOR"), exchange()).block();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("ticket", "ticket-1").containsEntry("expiresInSeconds", 30L);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
    }

    @Test
    void withoutAValidJwtThereIsNoTicket() {
        for (String header : new String[]{null, "", "Bearer basura", token("driver-1", "CONDUCTOR")}) {
            assertThat(controller.issue(header, exchange()).block().getStatusCode()).as(String.valueOf(header))
                    .isEqualTo(HttpStatus.UNAUTHORIZED);
        }
        verify(tickets, never()).issue(any(), any());
    }

    @Test
    void ifRedisFailsTheClientGets503() {
        when(tickets.issue(any(), any())).thenReturn(Mono.error(new IllegalStateException("Redis caído")));

        assertThat(controller.issue("Bearer " + token("coord-1", "COORDINADOR"), exchange()).block().getStatusCode())
                .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }
}
