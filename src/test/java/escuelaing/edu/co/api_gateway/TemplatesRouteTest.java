package escuelaing.edu.co.api_gateway;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * KAN-32 / KAN-84: /api/v1/templates/** llega a Notifications (TRUCKCAR_NOTIFICATIONS_URL) solo con un token ADMIN.
 * Notifications es un MockWebServer: así se ve exactamente qué le reenvía el gateway (ruta, método, cuerpo y
 * cabeceras) y que a un rol distinto, o sin token, no le llega nada.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TemplatesRouteTest {

    private static final String SECRET = "dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=";
    private static final String TEMPLATE_ID = "dc341a97-7bb9-460d-9b79-f2b4f2364c03";
    private static final MockWebServer NOTIFICATIONS = new MockWebServer();

    static {
        try {
            NOTIFICATIONS.start();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("app.jwt.secret", () -> SECRET);
        registry.add("TRUCKCAR_NOTIFICATIONS_URL", () -> "http://localhost:" + NOTIFICATIONS.getPort());
    }

    @AfterAll
    static void stopNotifications() throws IOException {
        NOTIFICATIONS.shutdown();
    }

    @Autowired
    private WebTestClient client;

    @LocalServerPort
    private int port;

    @BeforeEach
    void drainRecordedRequests() throws InterruptedException {
        while (NOTIFICATIONS.takeRequest(10, TimeUnit.MILLISECONDS) != null) {
            // descarta lo que haya quedado de otra prueba
        }
    }

    private static String token(String subject, String role) {
        return Jwts.builder().subject(subject).claim("role", role)
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 3_600_000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET))).compact();
    }

    private static MockResponse json(String body) {
        return new MockResponse().setResponseCode(200)
                .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(body);
    }

    @Test
    void anAdminReadingTemplateOneIsRoutedToNotificationsWithItsOwnJwt() throws InterruptedException {
        String admin = token("admin-1", "ADMIN");
        NOTIFICATIONS.enqueue(json("{\"id\":\"1\",\"category\":\"CAMBIO_ESTADO_VIAJE\"}"));

        client.get().uri("/api/v1/templates/1").header(HttpHeaders.AUTHORIZATION, "Bearer " + admin)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("{\"id\":\"1\",\"category\":\"CAMBIO_ESTADO_VIAJE\"}");

        RecordedRequest forwarded = NOTIFICATIONS.takeRequest(5, TimeUnit.SECONDS);
        assertThat(forwarded).as("la petición llegó a TRUCKCAR_NOTIFICATIONS_URL").isNotNull();
        assertThat(forwarded.getMethod()).isEqualTo("GET");
        assertThat(forwarded.getPath()).isEqualTo("/api/v1/templates/1");
        // Notifications valida su propio JWT (JwtTokenProvider): el gateway reenvía Authorization sin tocarla.
        assertThat(forwarded.getHeader(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + admin);
        assertThat(forwarded.getHeader("X-Auth-User")).isEqualTo("admin-1");
        assertThat(forwarded.getHeader("X-Auth-Role")).isEqualTo("ADMIN");
        assertThat(forwarded.getHeader("X-Correlation-Id")).isNotBlank();
    }

    @Test
    void theListAndTheUpdateReachNotificationsWithPathMethodAndBody() throws InterruptedException {
        String admin = token("admin-1", "ADMIN");
        NOTIFICATIONS.enqueue(json("[]"));
        NOTIFICATIONS.enqueue(json("{\"id\":\"" + TEMPLATE_ID + "\"}"));
        String body = "{\"templateText\":\"Carga {{loadId}}: {{status}}\"}";

        client.get().uri("/api/v1/templates").header(HttpHeaders.AUTHORIZATION, "Bearer " + admin)
                .exchange().expectStatus().isOk();
        client.put().uri("/api/v1/templates/" + TEMPLATE_ID).header(HttpHeaders.AUTHORIZATION, "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body)
                .exchange().expectStatus().isOk();

        RecordedRequest list = NOTIFICATIONS.takeRequest(5, TimeUnit.SECONDS);
        assertThat(list.getMethod()).isEqualTo("GET");
        assertThat(list.getPath()).isEqualTo("/api/v1/templates");
        RecordedRequest update = NOTIFICATIONS.takeRequest(5, TimeUnit.SECONDS);
        assertThat(update.getMethod()).isEqualTo("PUT");
        assertThat(update.getPath()).isEqualTo("/api/v1/templates/" + TEMPLATE_ID);
        assertThat(update.getBody().readUtf8()).isEqualTo(body);
    }

    @Test
    void anyOtherRoleGets403FromTheGatewayAndNothingReachesNotifications() throws InterruptedException {
        for (String role : new String[] {"CONDUCTOR", "COORDINADOR", "GENERADOR"}) {
            client.get().uri("/api/v1/templates").header(HttpHeaders.AUTHORIZATION, "Bearer " + token("u-" + role, role))
                    .exchange()
                    .expectStatus().isForbidden()
                    .expectBody()
                    .jsonPath("$.status").isEqualTo(403)
                    .jsonPath("$.message").isEqualTo("Esta ruta solo está disponible para administradores");
        }
        // Un conductor que además inventa X-Auth-Role: ADMIN tampoco pasa.
        client.put().uri("/api/v1/templates/" + TEMPLATE_ID)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token("u-1", "CONDUCTOR"))
                .header("X-Auth-Role", "ADMIN").contentType(MediaType.APPLICATION_JSON).bodyValue("{\"templateText\":\"x\"}")
                .exchange().expectStatus().isForbidden();

        assertThat(NOTIFICATIONS.takeRequest(300, TimeUnit.MILLISECONDS)).as("no llegó nada a Notifications").isNull();
    }

    @Test
    void pathTricksThroughTheNotificationsRouteAreStoppedByTheGatewayItself() throws InterruptedException {
        String conductor = token("u-1", "CONDUCTOR");
        for (String path : new String[] {"/api/v1/notifications/../templates", "/api/v1/notifications/%2e%2e/templates",
                "/api/v1/templates;x=1"}) {
            client.get().uri(URI.create("http://localhost:" + port + path))
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + conductor)
                    .exchange()
                    .expectStatus().isForbidden()
                    .expectBody().jsonPath("$.message").isEqualTo("Esta ruta solo está disponible para administradores");
        }
        assertThat(NOTIFICATIONS.takeRequest(300, TimeUnit.MILLISECONDS))
                .as("el gateway no depende de que Notifications lo frene").isNull();
    }

    @Test
    void withoutATokenTheGatewayAnswers401AndNothingReachesNotifications() throws InterruptedException {
        client.get().uri("/api/v1/templates").exchange()
                .expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.status").isEqualTo(401);

        assertThat(NOTIFICATIONS.takeRequest(300, TimeUnit.MILLISECONDS)).isNull();
    }
}
