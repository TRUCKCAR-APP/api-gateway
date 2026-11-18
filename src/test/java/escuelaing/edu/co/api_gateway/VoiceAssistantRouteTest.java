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
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * /api/v1/assistant/** llega a Voice-AI-Assistant (TRUCKCAR_VOICE_AI_ASSISTANT_URL) solo con un JWT válido y con la
 * identidad en X-Auth-User. El servicio es un MockWebServer. Sin Redis el limitador deja pasar (fail-open).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VoiceAssistantRouteTest {

    private static final String SECRET = "dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI=";
    private static final String BODY = "{\"text\":\"se vino la montaña\",\"context\":{\"navigating\":true}}";
    private static final MockWebServer ASSISTANT = new MockWebServer();

    static {
        try {
            ASSISTANT.start();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("app.jwt.secret", () -> SECRET);
        registry.add("TRUCKCAR_VOICE_AI_ASSISTANT_URL", () -> "http://localhost:" + ASSISTANT.getPort());
    }

    @AfterAll
    static void stop() throws IOException {
        ASSISTANT.shutdown();
    }

    @Autowired
    private WebTestClient client;

    @BeforeEach
    void drain() throws InterruptedException {
        while (ASSISTANT.takeRequest(10, TimeUnit.MILLISECONDS) != null) {
            // descarta lo que haya quedado de otra prueba
        }
    }

    private static String token(String subject, String role) {
        return Jwts.builder().subject(subject).claim("role", role)
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 3_600_000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET))).compact();
    }

    @Test
    void aDriverReachesTheAssistantWithItsIdentity() throws InterruptedException {
        ASSISTANT.enqueue(new MockResponse().setResponseCode(200)
                .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .setBody("{\"intent\":\"REPORT\",\"alertType\":\"landslide\"}"));

        client.post().uri("/api/v1/assistant/interpret")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token("driver-7", "CONDUCTOR"))
                // Un X-Auth-User inventado por el cliente se reemplaza por el del token.
                .header("X-Auth-User", "otro-conductor")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.intent").isEqualTo("REPORT");

        RecordedRequest forwarded = ASSISTANT.takeRequest(5, TimeUnit.SECONDS);
        assertThat(forwarded).as("la petición llegó a TRUCKCAR_VOICE_AI_ASSISTANT_URL").isNotNull();
        assertThat(forwarded.getMethod()).isEqualTo("POST");
        assertThat(forwarded.getPath()).isEqualTo("/api/v1/assistant/interpret");
        assertThat(forwarded.getHeader("X-Auth-User")).isEqualTo("driver-7");
        assertThat(forwarded.getHeader("X-Auth-Role")).isEqualTo("CONDUCTOR");
        assertThat(forwarded.getBody().readUtf8()).isEqualTo(BODY);
    }

    @Test
    void withoutATokenNothingReachesTheAssistant() throws InterruptedException {
        client.post().uri("/api/v1/assistant/interpret").contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange()
                .expectStatus().isUnauthorized();
        assertThat(ASSISTANT.takeRequest(300, TimeUnit.MILLISECONDS)).isNull();
    }
}
