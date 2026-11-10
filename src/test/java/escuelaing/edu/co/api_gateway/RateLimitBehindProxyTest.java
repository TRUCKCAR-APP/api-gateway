package escuelaing.edu.co.api_gateway;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Límite de intentos (KAN-31) como corre en Kubernetes: detrás del ALB, con TRUCKCAR_RATE_LIMIT_TRUST_FORWARDED_FOR=true
 * (k8s/base/platform-config.yaml). La conexión llega desde 127.0.0.1, que hace de ALB, y el ALB agrega al final de
 * X-Forwarded-For la IP pública del teléfono.
 * <p>
 * Se prueba con las dos estrategias de cabeceras reenviadas: la que Spring Boot activa sola en Kubernetes (native, en
 * la que Reactor Netty reescribe la dirección remota con X-Forwarded-For) y "none". El limitador lee X-Forwarded-For
 * desde la derecha por su cuenta, así que debe comportarse igual en ambas.
 */
@Testcontainers
class RateLimitBehindProxyTest {

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine"))
            .withExposedPorts(6379);

    private static final String LOGIN_BODY = "{\"email\":\"x@x.com\",\"password\":\"incorrecta\"}";

    abstract static class BehindTheAlb {

        @LocalServerPort
        private int port;

        @BeforeEach
        void emptyBuckets() throws Exception {
            REDIS.execInContainer("redis-cli", "FLUSHALL");
        }

        private int login(String forwardedFor) {
            return WebTestClient.bindToServer().baseUrl("http://127.0.0.1:" + port).build()
                    .post().uri("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                    .header("X-Forwarded-For", forwardedFor).bodyValue(LOGIN_BODY)
                    .exchange().returnResult(String.class).getStatus().value();
        }

        @Test
        void anAttackerRotatingTheForgedPartStillHitsTheLimit() {
            List<Integer> codes = new ArrayList<>();
            for (int i = 0; i < 15; i++) {
                // El atacante inventa la parte izquierda; el ALB siempre agrega su IP real al final.
                codes.add(login("203.0.113." + i + ", 181.50.3.7"));
            }
            assertThat(codes).contains(429);
        }

        @Test
        void differentPhonesBehindTheSameAlbDoNotShareABucket() throws Exception {
            List<Integer> codes = new ArrayList<>();
            for (int i = 0; i < 15; i++) {
                codes.add(login("181.50.3." + i));   // 15 teléfonos distintos, un intento cada uno
            }
            assertThat(codes).doesNotContain(429);
            String keys = REDIS.execInContainer("redis-cli", "--scan", "--pattern", "request_rate_limiter*tokens").getStdout();
            assertThat(keys).contains("{auth:user-identity-login-route:181.50.3.7}").doesNotContain("127.0.0.1");
        }
    }

    /** Lo que Spring Boot hace solo en Kubernetes (main hoy): forward-headers-strategy=native. */
    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    @TestPropertySource(properties = {
            "spring.main.cloud-platform=kubernetes",
            "gateway.rate-limit.trust-forwarded-for=true",
            "gateway.rate-limit.trusted-proxies=1",
            "app.jwt.secret=dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=",
            "TRUCKCAR_USER_IDENTITY_URL=http://127.0.0.1:9"
    })
    class KubernetesDefaultForwardHeaders extends BehindTheAlb {
    }

    /** Con forward-headers-strategy=none (la dirección remota es siempre la del ALB). */
    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    @TestPropertySource(properties = {
            "spring.main.cloud-platform=kubernetes",
            "server.forward-headers-strategy=none",
            "gateway.rate-limit.trust-forwarded-for=true",
            "gateway.rate-limit.trusted-proxies=1",
            "app.jwt.secret=dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=",
            "TRUCKCAR_USER_IDENTITY_URL=http://127.0.0.1:9"
    })
    class ForwardHeadersNone extends BehindTheAlb {
    }
}
