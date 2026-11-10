package escuelaing.edu.co.api_gateway.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PathNormalizationTest {

    @Test
    void normalizesLikeASpringServiceWould() {
        assertThat(PathNormalization.normalize("/api/v1/notifications/../templates")).isEqualTo("/api/v1/templates");
        assertThat(PathNormalization.normalize("/api/v1/notifications/%2e%2e/templates")).isEqualTo("/api/v1/templates");
        assertThat(PathNormalization.normalize("/api/v1/templates;x=1/abc")).isEqualTo("/api/v1/templates/abc");
        assertThat(PathNormalization.normalize("//api/v1//templates/")).isEqualTo("/api/v1/templates");
        assertThat(PathNormalization.normalize("/api/v1/%74emplates")).isEqualTo("/api/v1/templates");
        assertThat(PathNormalization.normalize("/API/V1/Templates")).isEqualTo("/api/v1/templates");
        assertThat(PathNormalization.normalize("/../../etc")).isEqualTo("/etc");
        assertThat(PathNormalization.normalize("/api/v1/templates/%zz")).isEqualTo("/api/v1/templates/%zz");
        assertThat(PathNormalization.normalize(null)).isEqualTo("/");
    }
}
