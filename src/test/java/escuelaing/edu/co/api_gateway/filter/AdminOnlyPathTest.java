package escuelaing.edu.co.api_gateway.filter;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** KAN-32: la regla "solo ADMIN" de /api/v1/templates decide sobre la ruta normalizada, no sobre el texto crudo. */
class AdminOnlyPathTest {

    /** Variantes probadas en vivo el 2026-11-10: el gateway las reenviaba y solo Notifications respondía 403. */
    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/templates",
            "/api/v1/templates/",
            "/api/v1/templates/57d7950b-b68c-4b8f-8eb6-d0167cf04b62",
            "/api/v1/%74emplates",
            "/api/v1/notifications/../templates",
            "/api/v1/notifications/%2e%2e/templates",
            "/api/v1/notifications/..%2ftemplates",
            "/api/v1/templates;x=1",
            "/api/v1/loads/../templates/abc"
    })
    void everyFormOfTheTemplatesPathIsAdminOnly(String rawPath) {
        assertThat(JwtAuthenticationFilter.adminOnly(rawPath)).as(rawPath).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/notifications/user/85787f20-0c4b-425b-b435-a12dd4b39f8b",
            "/api/v1/notifications",
            "/api/v1/templatesx",
            "/api/v1/loads/templates",
            "/api/v1/templates/../loads"
    })
    void otherPathsAreNotAdminOnly(String rawPath) {
        assertThat(JwtAuthenticationFilter.adminOnly(rawPath)).as(rawPath).isFalse();
    }
}
