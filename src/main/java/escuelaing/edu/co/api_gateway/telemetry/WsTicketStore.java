package escuelaing.edu.co.api_gateway.telemetry;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Tickets de un solo uso para abrir /ws-telemetry sin poner el JWT en la URL (que quedaría en los logs del balanceador
 * y de nginx). El ticket es un UUID aleatorio guardado en Redis con la identidad ya validada y una vida corta; se
 * canjea con GETDEL, así que un segundo intento con el mismo ticket, o uno vencido, no autentica. Redis lo comparten
 * las réplicas del gateway: el ticket que emite una sirve en otra.
 */
@Component
public class WsTicketStore {

    static final String KEY_PREFIX = "ws-ticket:";
    private static final Pattern UUID_FORMAT =
            Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    private final ReactiveStringRedisTemplate redis;
    private final Duration ttl;

    public WsTicketStore(ReactiveStringRedisTemplate redis,
                         @Value("${truckcar.telemetry.ws-ticket-ttl:30s}") Duration ttl) {
        this.redis = redis;
        this.ttl = ttl;
    }

    public Duration ttl() {
        return ttl;
    }

    /** Guarda la identidad del JWT y devuelve el ticket. */
    public Mono<String> issue(String userId, String role) {
        String ticket = UUID.randomUUID().toString();
        return redis.opsForValue().set(KEY_PREFIX + ticket, userId + "\n" + (role == null ? "" : role), ttl)
                .flatMap(stored -> Boolean.TRUE.equals(stored)
                        ? Mono.just(ticket)
                        : Mono.error(new IllegalStateException("Redis no guardó el ticket del WebSocket")));
    }

    /** Devuelve la identidad y borra el ticket en la misma operación; vacío si no existe, ya se usó o venció. */
    public Mono<TicketOwner> redeem(String ticket) {
        if (ticket == null || !UUID_FORMAT.matcher(ticket).matches()) {
            return Mono.empty();
        }
        return redis.opsForValue().getAndDelete(KEY_PREFIX + ticket).map(TicketOwner::parse);
    }

    public record TicketOwner(String userId, String role) {
        static TicketOwner parse(String value) {
            int separator = value.indexOf('\n');
            return separator < 0
                    ? new TicketOwner(value, "")
                    : new TicketOwner(value.substring(0, separator), value.substring(separator + 1));
        }
    }
}
