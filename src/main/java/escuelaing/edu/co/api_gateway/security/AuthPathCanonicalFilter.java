package escuelaing.edu.co.api_gateway.security;

import escuelaing.edu.co.api_gateway.error.GatewayErrors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * El límite de intentos (KAN-31) se aplica por ruta exacta: /api/v1/auth/login, /register y /refresh. Variantes como
 * /api/v1/auth//login o /api/v1/auth/%6Cogin no coinciden con esas rutas, caen en la general /api/v1/auth/** (sin
 * límite) y User-Identity las normaliza a /login: probar contraseñas sin límite. Bajo /api/v1/auth solo se aceptan
 * rutas canónicas; el resto responde 400 sin llegar al servicio.
 * <p>
 * No canónica: barras dobles, caracteres codificados con %, segmentos "." o "..", parámetros con ";" o "\". Ninguna
 * ruta legítima de autenticación los usa (la PWA envía /api/v1/auth/login tal cual).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class AuthPathCanonicalFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthPathCanonicalFilter.class);
    private static final String AUTH_PREFIX = "/api/v1/auth";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String raw = exchange.getRequest().getURI().getRawPath();
        if (raw == null || !targetsAuth(raw) || isCanonical(raw)) {
            return chain.filter(exchange);
        }
        log.warn("Ruta no canónica hacia /api/v1/auth rechazada: {} {}", exchange.getRequest().getMethod(), raw);
        return GatewayErrors.write(exchange, HttpStatus.BAD_REQUEST, "Solicitud inválida",
                "La ruta de autenticación no es válida");
    }

    /** ¿La ruta, una vez decodificada y normalizada como lo haría el servicio, apunta a /api/v1/auth? */
    static boolean targetsAuth(String rawPath) {
        return PathNormalization.isUnder(rawPath, AUTH_PREFIX);
    }

    static boolean isCanonical(String rawPath) {
        if (rawPath.contains("//") || rawPath.contains("%") || rawPath.contains(";") || rawPath.contains("\\")) {
            return false;
        }
        for (String segment : rawPath.split("/")) {
            if (segment.equals(".") || segment.equals("..")) {
                return false;
            }
        }
        return true;
    }
}
