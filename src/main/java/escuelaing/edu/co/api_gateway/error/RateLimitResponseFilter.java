package escuelaing.edu.co.api_gateway.error;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Complementa el RequestRateLimiter de las rutas de /api/v1/auth:
 * <ul>
 *   <li>El filtro de Spring Cloud Gateway responde 429 sin cuerpo. Aquí se le da el JSON normalizado del gateway
 *       (mensaje "Demasiados intentos, espere unos segundos") y la cabecera Retry-After, calculada con las
 *       X-RateLimit-* que dejó el limitador.</li>
 *   <li>Si Redis no responde, RedisRateLimiter deja pasar la petición (fail-open) y marca X-RateLimit-Remaining=-1.
 *       Esas peticiones se cuentan en truckcar_gateway_rate_limiter_fail_open_total para alertar (el login sigue
 *       funcionando, pero sin protección contra fuerza bruta).</li>
 * </ul>
 * Va antes del JwtAuthenticationFilter (-1) para que el resto de la cadena use la respuesta decorada.
 */
@Component
public class RateLimitResponseFilter implements GlobalFilter, Ordered {

    public static final String MESSAGE = "Demasiados intentos, espere unos segundos";
    static final String REMAINING = "X-RateLimit-Remaining";
    static final String REPLENISH_RATE = "X-RateLimit-Replenish-Rate";
    static final String REQUESTED_TOKENS = "X-RateLimit-Requested-Tokens";

    private static final Logger log = LoggerFactory.getLogger(RateLimitResponseFilter.class);

    private final Counter failOpen;

    public RateLimitResponseFilter(MeterRegistry registry) {
        this.failOpen = Counter.builder("truckcar.gateway.rate.limiter.fail.open")
                .description("Peticiones a rutas con límite que pasaron sin control porque Redis no respondió")
                .register(registry);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpResponse original = exchange.getResponse();
        ServerHttpResponseDecorator response = new ServerHttpResponseDecorator(original) {
            @Override
            public Mono<Void> setComplete() {
                HttpStatusCode status = getStatusCode();
                if (status != null && status.value() == HttpStatus.TOO_MANY_REQUESTS.value() && !isCommitted()) {
                    getHeaders().set(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfterSeconds(getHeaders())));
                    return GatewayErrors.write(exchange, HttpStatus.TOO_MANY_REQUESTS, "Demasiadas solicitudes",
                            MESSAGE);
                }
                return super.setComplete();
            }
        };
        response.beforeCommit(() -> {
            if ("-1".equals(original.getHeaders().getFirst(REMAINING))) {
                failOpen.increment();
                log.warn("Límite de intentos sin Redis: {} {} pasó sin control (fail-open)",
                        exchange.getRequest().getMethod(), exchange.getRequest().getPath());
            }
            return Mono.empty();
        });
        return chain.filter(exchange.mutate().response(response).build());
    }

    /** Segundos hasta que el cubo repone lo que pide una petición: requested / replenish, redondeado arriba (mín. 1). */
    static long retryAfterSeconds(HttpHeaders headers) {
        try {
            double replenish = Double.parseDouble(headers.getFirst(REPLENISH_RATE));
            String requestedHeader = headers.getFirst(REQUESTED_TOKENS);
            double requested = requestedHeader == null ? 1 : Double.parseDouble(requestedHeader);
            if (replenish > 0) {
                return Math.max(1, (long) Math.ceil(requested / replenish));
            }
        } catch (NullPointerException | NumberFormatException e) {
            // Sin cabeceras del limitador: un segundo es un valor prudente.
        }
        return 1;
    }

    @Override
    public int getOrder() {
        return -2;
    }
}
