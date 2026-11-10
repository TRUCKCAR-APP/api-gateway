package escuelaing.edu.co.api_gateway.error;

import io.netty.channel.ConnectTimeoutException;
import io.netty.handler.timeout.ReadTimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

/**
 * Errores producidos en el propio gateway (ruta inexistente, servicio caído, timeouts, cuerpo inválido...) con el
 * cuerpo JSON normalizado de {@link GatewayErrors}. Sin este handler Spring respondía con su formato por defecto y un
 * servicio caído ("Connection refused") llegaba al cliente como 500 en lugar de 503. Las respuestas de error de los
 * microservicios no pasan por aquí: se reenvían tal cual.
 */
@Component
@Order(-2) // antes que el DefaultErrorWebExceptionHandler de Spring Boot (-1)
public class GatewayErrorHandler implements ErrorWebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GatewayErrorHandler.class);

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }
        Mapped mapped = map(ex);
        if (mapped.status().is5xxServerError()) {
            log.warn("{} {} -> {}: {}", exchange.getRequest().getMethod(), exchange.getRequest().getPath(),
                    mapped.status().value(), ex.toString());
        }
        return GatewayErrors.write(exchange, mapped.status(), mapped.error(), mapped.message());
    }

    static Mapped map(Throwable ex) {
        Throwable cause = rootCause(ex);
        if (cause instanceof ConnectException || cause instanceof UnknownHostException
                || cause instanceof ConnectTimeoutException) {
            return new Mapped(HttpStatus.SERVICE_UNAVAILABLE, "Servicio no disponible",
                    "El servicio que atiende esta ruta no está disponible; intente de nuevo en unos segundos");
        }
        if (cause instanceof TimeoutException || cause instanceof ReadTimeoutException) {
            return new Mapped(HttpStatus.GATEWAY_TIMEOUT, "Tiempo de espera agotado",
                    "El servicio que atiende esta ruta no respondió a tiempo");
        }
        if (ex instanceof ResponseStatusException rse) {
            HttpStatusCode status = rse.getStatusCode();
            return new Mapped(status, titleFor(status), messageFor(status, rse));
        }
        return new Mapped(HttpStatus.INTERNAL_SERVER_ERROR, "Error interno",
                "El gateway no pudo procesar la solicitud");
    }

    private static String titleFor(HttpStatusCode status) {
        HttpStatus known = HttpStatus.resolve(status.value());
        if (known == null) {
            return status.is4xxClientError() ? "Solicitud inválida" : "Error del servidor";
        }
        return switch (known) {
            case BAD_REQUEST -> "Solicitud inválida";
            case NOT_FOUND -> "Ruta no encontrada";
            case METHOD_NOT_ALLOWED -> "Método no permitido";
            case PAYLOAD_TOO_LARGE -> "Solicitud demasiado grande";
            case UNSUPPORTED_MEDIA_TYPE -> "Tipo de contenido no soportado";
            case SERVICE_UNAVAILABLE -> "Servicio no disponible";
            case GATEWAY_TIMEOUT -> "Tiempo de espera agotado";
            default -> status.is4xxClientError() ? "Solicitud inválida" : "Error del servidor";
        };
    }

    /** Mensaje para el cliente: el reason de la excepción solo si es un error del cliente (no expone internos). */
    private static String messageFor(HttpStatusCode status, ResponseStatusException rse) {
        if (status.value() == HttpStatus.NOT_FOUND.value()) {
            return "No existe un recurso para esta ruta en la API";
        }
        if (status.value() == HttpStatus.SERVICE_UNAVAILABLE.value()) {
            return "El servicio que atiende esta ruta no está disponible; intente de nuevo en unos segundos";
        }
        if (status.value() == HttpStatus.GATEWAY_TIMEOUT.value()) {
            return "El servicio que atiende esta ruta no respondió a tiempo";
        }
        if (status.is4xxClientError() && rse.getReason() != null && !rse.getReason().isBlank()) {
            return rse.getReason();
        }
        return status.is4xxClientError() ? "La solicitud no es válida" : "El gateway no pudo procesar la solicitud";
    }

    private static Throwable rootCause(Throwable ex) {
        Throwable current = ex;
        for (int depth = 0; current.getCause() != null && current.getCause() != current && depth < 10; depth++) {
            if (current instanceof ConnectException || current instanceof TimeoutException) {
                return current;
            }
            current = current.getCause();
        }
        return current;
    }

    record Mapped(HttpStatusCode status, String error, String message) {
    }
}
