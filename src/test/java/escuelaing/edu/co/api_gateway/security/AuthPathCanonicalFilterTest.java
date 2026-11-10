package escuelaing.edu.co.api_gateway.security;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/** Variantes de /api/v1/auth/login que esquivarían el límite de intentos (KAN-31). */
class AuthPathCanonicalFilterTest {

    private final AuthPathCanonicalFilter filter = new AuthPathCanonicalFilter();

    private boolean forwards(String rawPath) {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.method(HttpMethod.POST, URI.create(rawPath)).build());
        AtomicBoolean forwarded = new AtomicBoolean();
        filter.filter(exchange, ex -> {
            forwarded.set(true);
            return Mono.empty();
        }).block();
        if (!forwarded.get()) {
            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
        return forwarded.get();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/auth//login",          // probado en vivo: User-Identity lo atendía como /login, sin límite
            "/api/v1/auth/%6Cogin",         // probado en vivo: "l" codificada
            "/api/v1/auth/log%69n",
            "/api/v1/auth/%2e/login",
            "/api/v1/auth/./login",
            "/api/v1/auth/x/../login",
            "/api/v1/auth/login;x=1",
            "/api/v1//auth/login",
            "/api/v1/%61uth/login",
            "/api/v1/AUTH//login",
            "/api/v1/loads/../auth/login"
    })
    void nonCanonicalAuthPathsAreRejected(String path) {
        assertThat(forwards(path)).as(path).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/v1/auth/logout",
            "/api/v1/auth/login/",            // barra final: la ruta limitada también la atiende
            "/api/v1/loads/public-tracking/abc.def",
            "/api/v1/routes/history/TDK%20410", // fuera de /auth, los caracteres codificados siguen permitidos
            "/api/v1/users/me",
            "/ws-telemetry"
    })
    void canonicalAndNonAuthPathsPass(String path) {
        assertThat(forwards(path)).as(path).isTrue();
    }
}
