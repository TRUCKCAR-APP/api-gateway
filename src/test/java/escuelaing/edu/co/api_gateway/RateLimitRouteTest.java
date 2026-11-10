package escuelaing.edu.co.api_gateway;

import escuelaing.edu.co.api_gateway.error.RateLimitResponseFilter;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * KAN-31: límite de intentos en /api/v1/auth/login, /register y /refresh con RequestRateLimiter y Redis real
 * (redis:7.4-alpine). User-Identity es un servidor falso: /login siempre responde 401 (credenciales incorrectas), como
 * en un ataque de fuerza bruta. Límites por defecto: login 1/s con ráfaga de 5; register/refresh 5/s con ráfaga de 10.
 * Requiere Docker (Testcontainers): sin él la prueba falla en lugar de omitirse en silencio.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RateLimitRouteTest {

    private static final String SECRET = "dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=";
    private static final String LOGIN_BODY = "{\"email\":\"x@x.com\",\"password\":\"incorrecta\"}";

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine"))
            .withExposedPorts(6379);

    /** User-Identity falso: login → 401, register → 201, /users/me → 200 con el X-Auth-User que puso el gateway. */
    static final DisposableServer USER_IDENTITY = HttpServer.create().host("localhost").port(0)
            .route(routes -> routes
                    .post("/api/v1/auth/login", (req, res) -> res.status(401)
                            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                            .sendString(Mono.just("{\"status\":401,\"message\":\"Credenciales inválidas\"}")))
                    .post("/api/v1/auth/register", (req, res) -> res.status(201)
                            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                            .sendString(Mono.just("{}")))
                    .get("/api/v1/users/me", (req, res) -> res.status(200)
                            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                            .sendString(Mono.just("{\"id\":\"" + req.requestHeaders().get("X-Auth-User") + "\"}"))))
            .bindNow();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("app.jwt.secret", () -> SECRET);
        registry.add("TRUCKCAR_USER_IDENTITY_URL", () -> "http://localhost:" + USER_IDENTITY.port());
        registry.add("spring.data.redis.timeout", () -> "1s");
        registry.add("spring.data.redis.connect-timeout", () -> "1s");
    }

    @AfterAll
    static void stopUserIdentity() {
        USER_IDENTITY.disposeNow();
    }

    @Autowired
    private WebTestClient client;

    @Autowired
    private MeterRegistry meters;

    @LocalServerPort
    private int port;

    @BeforeEach
    void emptyBuckets() throws Exception {
        if (REDIS.isRunning()) {
            REDIS.execInContainer("redis-cli", "FLUSHALL");
        }
        client = client.mutate().responseTimeout(Duration.ofSeconds(10)).build();
    }

    private EntityExchangeResult<String> login(String forwardedFor) {
        WebTestClient.RequestBodySpec request = client.post().uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON);
        if (forwardedFor != null) {
            request.header("X-Forwarded-For", forwardedFor);
        }
        return request.bodyValue(LOGIN_BODY).exchange().expectBody(String.class).returnResult();
    }

    private static List<Integer> statuses(List<EntityExchangeResult<String>> results) {
        return results.stream().map(r -> r.getStatus().value()).toList();
    }

    @Test
    @Order(1)
    void fifteenFailedLoginsInARowGetCutOffWith429() {
        List<EntityExchangeResult<String>> results = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            results.add(login(null));
        }

        List<Integer> codes = statuses(results);
        assertThat(codes).as("la ráfaga permitida llega a User-Identity").startsWith(401, 401, 401, 401, 401);
        assertThat(codes).as("al agotar el cubo responde 429").contains(429);
        assertThat(codes).containsOnly(401, 429);
    }

    @Test
    @Order(2)
    void the429HasTheNormalizedJsonRetryAfterAndRateLimitHeaders() {
        EntityExchangeResult<String> limited = null;
        for (int i = 0; i < 15 && limited == null; i++) {
            EntityExchangeResult<String> result = login(null);
            if (result.getStatus() == HttpStatus.TOO_MANY_REQUESTS) {
                limited = result;
            }
        }

        assertThat(limited).as("algún intento recibió 429").isNotNull();
        HttpHeaders headers = limited.getResponseHeaders();
        assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(headers.getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("1");
        assertThat(headers.getFirst("X-RateLimit-Remaining")).isEqualTo("0");
        assertThat(headers.getFirst("X-RateLimit-Replenish-Rate")).isEqualTo("1");
        assertThat(headers.getFirst("X-RateLimit-Burst-Capacity")).isEqualTo("5");
        assertThat(headers.getFirst("X-Correlation-Id")).isNotBlank();
        assertThat(limited.getResponseBody())
                .contains("\"status\":429")
                .contains("\"message\":\"" + RateLimitResponseFilter.MESSAGE + "\"")
                .contains("\"path\":\"/api/v1/auth/login\"");
    }

    @Test
    @Order(3)
    void aForgedForwardedForDoesNotOpenANewBucket() {
        List<EntityExchangeResult<String>> results = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            results.add(login("203.0.113." + i));   // una "IP" distinta en cada intento
        }

        assertThat(statuses(results)).contains(429);
    }

    @Test
    @Order(4)
    void otherRoutesAndOtherBucketsAreNotAffected() {
        for (int i = 0; i < 15; i++) {
            login(null);
        }
        assertThat(login(null).getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);

        // /users/me con un token válido no tiene límite.
        String token = Jwts.builder().subject("85787f20-0c4b-425b-b435-a12dd4b39f8b").claim("role", "CONDUCTOR")
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 3_600_000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET))).compact();
        for (int i = 0; i < 20; i++) {
            client.get().uri("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange().expectStatus().isOk()
                    .expectBody(String.class).isEqualTo("{\"id\":\"85787f20-0c4b-425b-b435-a12dd4b39f8b\"}");
        }

        // register tiene su propio cubo: el login agotado no lo bloquea.
        client.post().uri("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isCreated();
    }

    @Test
    @Order(5)
    void registerAndRefreshShareTheLooserBucket() {
        List<Integer> codes = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            codes.add(client.post().uri("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{}").exchange().expectBody(String.class).returnResult().getStatus().value());
        }

        assertThat(codes.subList(0, 10)).as("ráfaga de 10").containsOnly(201);
        assertThat(codes).contains(429);
    }

    @Test
    @Order(6)
    void variantsOfTheLoginPathCannotBypassTheLimit() {
        for (String path : new String[] {"/api/v1/auth//login", "/api/v1/auth/%6Cogin"}) {
            client.post().uri(URI.create("http://localhost:" + port + path)).contentType(MediaType.APPLICATION_JSON).bodyValue(LOGIN_BODY)
                    .exchange().expectStatus().isBadRequest()
                    .expectBody().jsonPath("$.message").isEqualTo("La ruta de autenticación no es válida");
        }
    }

    @Test
    @Order(7)
    void theLimiterKeysLiveInRedisWithATtl() throws Exception {
        login(null);

        String keys = REDIS.execInContainer("redis-cli", "--scan", "--pattern", "request_rate_limiter*").getStdout();
        assertThat(keys).contains("request_rate_limiter.{auth:user-identity-login-route:127.0.0.1}.tokens");
        String ttl = REDIS.execInContainer("redis-cli", "TTL",
                "request_rate_limiter.{auth:user-identity-login-route:127.0.0.1}.tokens").getStdout().trim();
        assertThat(Long.parseLong(ttl)).isPositive();
    }

    /** Último: apaga Redis. El login sigue llegando a User-Identity (fail-open), rápido y contado en la métrica. */
    @Test
    @Order(8)
    void withoutRedisLoginsPassFastAndAreCounted() {
        double before = failOpenCount();
        REDIS.stop();

        List<Integer> codes = new ArrayList<>();
        long start = System.nanoTime();
        for (int i = 0; i < 8; i++) {
            codes.add(login(null).getStatus().value());
        }
        long seconds = Duration.ofNanos(System.nanoTime() - start).toSeconds();

        assertThat(codes).as("sin Redis no hay 429: pasa todo").containsOnly(401);
        assertThat(seconds).as("cada intento espera como mucho el timeout de Redis (1 s), no 60 s").isLessThan(20);
        assertThat(failOpenCount() - before).isEqualTo(8);
    }

    private double failOpenCount() {
        var counter = meters.find("truckcar.gateway.rate.limiter.fail.open").counter();
        return counter == null ? 0 : counter.count();
    }
}
