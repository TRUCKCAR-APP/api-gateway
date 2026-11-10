package escuelaing.edu.co.api_gateway.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * KAN-33: CORS del gateway con los orígenes exactos de docker-compose (la PWA en :5500). Un preflight de un origen
 * ajeno no recibe Access-Control-Allow-Origin y, con el perfil prod, un comodín o localhost impide arrancar.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "gateway.cors.allowed-origins=http://localhost:5500,http://127.0.0.1:5500",
        "app.jwt.secret=dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI="
})
class CorsConfigTest {

    @Autowired
    private WebTestClient client;

    private WebTestClient.ResponseSpec preflight(String origin) {
        return client.options().uri("/api/v1/loads")
                .header(HttpHeaders.ORIGIN, origin)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                .exchange();
    }

    @Test
    void thePwaOriginPassesThePreflight() {
        preflight("http://localhost:5500")
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:5500")
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        preflight("http://127.0.0.1:5500")
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://127.0.0.1:5500");
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://evil.example", "http://localhost:3000", "https://localhost:5500",
            "http://evil.localhost:5500", "null"})
    void anyOtherOriginGetsNoAllowOriginHeader(String origin) {
        preflight(origin)
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
    }

    /** Antes respondían 500: Spring no podía analizar el puerto o el host IPv6 dentro del filtro CORS. */
    @ParameterizedTest
    @ValueSource(strings = {"http://localhost:5500.evil.example", "http://[zz", "http://localhost:99999999999"})
    void aMalformedOriginIsAClientError400NotA500(String origin) {
        preflight(origin)
                .expectStatus().isBadRequest()
                .expectHeader().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)
                .expectBody().jsonPath("$.status").isEqualTo(400);
        client.get().uri("/api/v1/loads").header(HttpHeaders.ORIGIN, origin)
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void identityHeadersAreNeverAllowedFromTheBrowser() {
        client.options().uri("/api/v1/loads")
                .header(HttpHeaders.ORIGIN, "http://localhost:5500")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "x-auth-role")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void theRateLimitHeadersAreExposedToThePwa() {
        client.get().uri("/api/v1/loads").header(HttpHeaders.ORIGIN, "http://localhost:5500")
                .exchange()
                .expectHeader().value(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, exposed -> assertThat(exposed)
                        .contains("X-Correlation-Id", "Retry-After", "X-RateLimit-Remaining"));
    }

    // ── Validación de producción ─────────────────────────────────────────────────────────────────────────────────

    private static MockEnvironment prod() {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(CorsConfig.PROD_PROFILE);
        return environment;
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost:*", "https://*.truckcar.co", "*", "http://localhost:5500",
            "http://127.0.0.1:5500", "https://app.truckcar.co, http://LOCALHOST:5500", "http://[::1]:5500"})
    void inProdAWildcardOrLocalhostStopsTheStartup(String origins) {
        assertThatThrownBy(() -> new CorsConfig(origins, prod()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("CORS de producción no admite comodines")
                .hasMessageContaining("TRUCKCAR_CORS_ALLOWED_ORIGINS");
    }

    @Test
    void inProdAnEmptyListStopsTheStartupToo() {
        assertThatThrownBy(() -> new CorsConfig(" , ", prod()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("está vacío");
    }

    @Test
    void inProdTheRealDomainsAreAccepted() {
        assertThatCode(() -> new CorsConfig("https://app.truckcar.co, http://k8s-truckcar-123.us-east-1.elb.amazonaws.com",
                prod())).doesNotThrowAnyException();
    }

    @Test
    void outsideProdTheDevelopmentWildcardIsStillAllowed() {
        assertThatCode(() -> new CorsConfig("http://localhost:*,http://127.0.0.1:*", new MockEnvironment()))
                .doesNotThrowAnyException();
        assertThat(CorsConfig.parse(" http://a.co , ,https://b.co ")).isEqualTo(List.of("http://a.co", "https://b.co"));
    }
}
