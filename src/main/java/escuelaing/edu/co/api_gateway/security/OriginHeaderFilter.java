package escuelaing.edu.co.api_gateway.security;

import escuelaing.edu.co.api_gateway.error.GatewayErrors;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/**
 * Una cabecera Origin mal formada (http://localhost:5500.evil.example, http://[zz) hacía fallar el análisis del
 * CorsWebFilter de Spring (IllegalStateException "The port must be an integer", IllegalArgumentException "Invalid IPV6
 * host") y el cliente recibía 500. Un navegador nunca envía algo así: es un error del cliente y se responde 400 antes
 * de llegar a CORS. "null" (archivos locales, iframes sandbox) es un Origin válido y lo decide CorsWebFilter.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
public class OriginHeaderFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String origin = exchange.getRequest().getHeaders().getFirst(HttpHeaders.ORIGIN);
        if (origin == null || isWellFormed(origin)) {
            return chain.filter(exchange);
        }
        return GatewayErrors.write(exchange, HttpStatus.BAD_REQUEST, "Solicitud inválida",
                "La cabecera Origin no es un origen válido (esquema://host[:puerto])");
    }

    /** El mismo análisis que hace Spring en CORS (fromOriginHeader), incluido el puerto, sin dejar escapar excepciones. */
    static boolean isWellFormed(String origin) {
        if ("null".equals(origin)) {
            return true;
        }
        try {
            UriComponents components = UriComponentsBuilder.fromOriginHeader(origin).build();
            components.getPort();
            return components.getScheme() != null && components.getHost() != null;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
