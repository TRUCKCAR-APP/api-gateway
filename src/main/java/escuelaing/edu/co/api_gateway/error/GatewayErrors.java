package escuelaing.edu.co.api_gateway.error;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cuerpo de error único del gateway, con la misma forma que usan los microservicios (timestamp, status, error,
 * message) más path y correlationId para rastrear la petición. Nunca incluye trazas ni detalles internos.
 */
public final class GatewayErrors {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private GatewayErrors() {
    }

    public static Map<String, Object> body(HttpStatusCode status, String error, String message, ServerWebExchange exchange) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", error);
        body.put("message", message);
        body.put("path", exchange.getRequest().getPath().value());
        String correlationId = exchange.getResponse().getHeaders().getFirst("X-Correlation-Id");
        if (correlationId == null) {
            correlationId = exchange.getRequest().getHeaders().getFirst("X-Correlation-Id");
        }
        if (correlationId != null) {
            body.put("correlationId", correlationId);
        }
        return body;
    }

    /** Escribe el error en la respuesta (si aún no se envió nada) con Content-Type JSON y sin caché. */
    public static Mono<Void> write(ServerWebExchange exchange, HttpStatusCode status, String error, String message) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return response.setComplete();
        }
        byte[] json;
        try {
            json = MAPPER.writeValueAsBytes(body(status, error, message, exchange));
        } catch (JsonProcessingException e) {
            json = ("{\"status\":" + status.value() + "}").getBytes(StandardCharsets.UTF_8);
        }
        response.setStatusCode(status);
        HttpHeaders headers = response.getHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setCacheControl("no-store");
        headers.setContentLength(json.length);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(json)));
    }
}
