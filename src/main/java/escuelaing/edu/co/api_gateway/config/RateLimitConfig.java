package escuelaing.edu.co.api_gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.Arrays;

/**
 * Límite de intentos en /api/v1/auth/login, /register y /refresh (KAN-31): RequestRateLimiter de Spring Cloud Gateway,
 * con un token bucket por IP del cliente guardado en Redis (claves request_rate_limiter.{auth:...}.tokens/.timestamp,
 * con TTL). Lo comparten todas las réplicas del gateway.
 * <p>
 * La clave incluye la ruta (login tiene su propio cubo, más estricto que register/refresh): RedisRateLimiter no la
 * agrega por su cuenta, y sin ella dos rutas con límites distintos gastarían el mismo cubo.
 */
@Configuration
public class RateLimitConfig {

    static final String UNKNOWN_CLIENT = "unknown";

    /**
     * IP del cliente:
     * <ul>
     *   <li>trust-forwarded-for=false (por defecto, Docker/local): la dirección de la conexión TCP. X-Forwarded-For se
     *       ignora, porque el cliente puede inventarlo para estrenar un cubo nuevo en cada intento.</li>
     *   <li>trust-forwarded-for=true (detrás del ALB, que se conecta al pod): la entrada de X-Forwarded-For que agregó el
     *       proxy de confianza más externo. Cada proxy añade al final la IP de quien le habló, así que se cuenta desde
     *       la derecha: con trusted-proxies=1 (solo el ALB) es la última. Lo que el cliente ponga más a la izquierda no
     *       cuenta. Con un túnel de Cloudflare delante del ALB son 2.</li>
     * </ul>
     */
    @Bean
    public KeyResolver clientIpKeyResolver(
            @Value("${gateway.rate-limit.trust-forwarded-for:false}") boolean trustForwardedFor,
            @Value("${gateway.rate-limit.trusted-proxies:1}") int trustedProxies) {
        int hops = Math.max(1, trustedProxies);
        return exchange -> {
            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            String scope = route == null ? "auth" : route.getId();
            return Mono.just("auth:" + scope + ":" + clientIp(exchange.getRequest(), trustForwardedFor, hops));
        };
    }

    static String clientIp(ServerHttpRequest request, boolean trustForwardedFor, int trustedProxies) {
        if (trustForwardedFor) {
            String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                String[] hops = Arrays.stream(forwarded.split(",")).map(String::trim).filter(s -> !s.isEmpty())
                        .toArray(String[]::new);
                if (hops.length > 0) {
                    return hops[Math.max(0, hops.length - trustedProxies)];
                }
            }
        }
        InetSocketAddress remote = request.getRemoteAddress();
        return remote != null && remote.getAddress() != null ? remote.getAddress().getHostAddress() : UNKNOWN_CLIENT;
    }
}
