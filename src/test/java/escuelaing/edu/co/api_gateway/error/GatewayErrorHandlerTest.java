package escuelaing.edu.co.api_gateway.error;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebInputException;

import java.net.ConnectException;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

class GatewayErrorHandlerTest {

    private final GatewayErrorHandler handler = new GatewayErrorHandler();

    private MockServerWebExchange handle(Throwable error) {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/loads/7")
                .header("X-Correlation-Id", "cid-1").build());
        handler.handle(exchange, error).block();
        return exchange;
    }

    @Test
    void downstreamServiceDownIs503InsteadOf500() {
        MockServerWebExchange exchange = handle(new RuntimeException(new ConnectException("Connection refused")));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(exchange.getResponse().getBodyAsString().block())
                .contains("\"status\":503", "no está disponible", "\"correlationId\":\"cid-1\"")
                .doesNotContain("Connection refused");
    }

    @Test
    void downstreamTimeoutIs504() {
        assertThat(handle(new TimeoutException("read")).getResponse().getStatusCode()).isEqualTo(HttpStatus.GATEWAY_TIMEOUT);
    }

    @Test
    void unknownRouteIsANormalized404() {
        MockServerWebExchange exchange = handle(new ResponseStatusException(HttpStatus.NOT_FOUND));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(exchange.getResponse().getBodyAsString().block())
                .contains("\"error\":\"Ruta no encontrada\"", "\"path\":\"/api/v1/loads/7\"");
    }

    @Test
    void clientInputErrorsStay400WithTheirReason() {
        MockServerWebExchange exchange = handle(new ServerWebInputException("Cuerpo ilegible"));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(exchange.getResponse().getBodyAsString().block()).contains("Cuerpo ilegible");
    }

    @Test
    void unexpectedErrorsDoNotLeakInternals() {
        MockServerWebExchange exchange = handle(new IllegalStateException("NullPointer en com.interno.Clase"));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(exchange.getResponse().getBodyAsString().block()).doesNotContain("com.interno");
    }
}
