package escuelaing.edu.co.api_gateway.telemetry;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** Contra el Redis local (pila de Docker): un ticket abre una sola conexión y caduca solo. */
class WsTicketStoreRedisTest {

    private static LettuceConnectionFactory connections;
    private static ReactiveStringRedisTemplate redis;

    @BeforeAll
    static void connect() {
        connections = new LettuceConnectionFactory(
                System.getenv().getOrDefault("SPRING_DATA_REDIS_HOST", "localhost"), 6379);
        connections.afterPropertiesSet();
        redis = new ReactiveStringRedisTemplate(connections);
    }

    @AfterAll
    static void close() {
        connections.destroy();
    }

    @Test
    void aTicketIsRedeemedOnceWithTheIdentityAndAShortLife() {
        WsTicketStore store = new WsTicketStore(redis, Duration.ofSeconds(30));

        String ticket = store.issue("driver-1", "CONDUCTOR").block();

        Duration life = redis.getExpire(WsTicketStore.KEY_PREFIX + ticket).block();
        assertThat(life).isPositive().isLessThanOrEqualTo(Duration.ofSeconds(30));
        assertThat(store.redeem(ticket).block()).isEqualTo(new WsTicketStore.TicketOwner("driver-1", "CONDUCTOR"));
        assertThat(store.redeem(ticket).block()).isNull();
        assertThat(redis.hasKey(WsTicketStore.KEY_PREFIX + ticket).block()).isFalse();
    }

    @Test
    void anExpiredTicketNoLongerAuthenticates() throws InterruptedException {
        WsTicketStore store = new WsTicketStore(redis, Duration.ofSeconds(1));
        String ticket = store.issue("coord-1", "COORDINADOR").block();

        Thread.sleep(1500);

        assertThat(store.redeem(ticket).block()).isNull();
    }

    @Test
    void anythingThatIsNotAUuidIsRejectedWithoutQueryingRedis() {
        WsTicketStore store = new WsTicketStore(redis, Duration.ofSeconds(30));

        assertThat(store.redeem(null).block()).isNull();
        assertThat(store.redeem("*").block()).isNull();
        assertThat(store.redeem("eyJhbGciOiJIUzI1NiJ9.e30.firma").block()).isNull();
    }
}
