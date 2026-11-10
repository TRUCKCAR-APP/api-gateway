package escuelaing.edu.co.api_gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Detrás del ALB, en Kubernetes: Spring Boot detecta la plataforma y, sin configuración explícita, activa
 * forward-headers-strategy=native, con lo que Reactor Netty toma la dirección remota de X-Forwarded-For. Así el
 * TrustedSourceFilter veía la IP pública del cliente y rechazaba con 403 todo el tráfico que llegaba por el ALB.
 * <p>
 * Aquí el servidor arranca de verdad (Netty, puerto aleatorio) como si estuviera en Kubernetes; la conexión llega desde
 * 127.0.0.1, que hace de ALB. El filtro debe decidir con esa IP y nunca con la de X-Forwarded-For.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "spring.main.cloud-platform=kubernetes",
        "gateway.trusted-source-cidrs=127.0.0.0/8,::1/128",
        "app.jwt.secret=dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI="
})
class TrustedSourceBehindProxyTest {

    @LocalServerPort
    private int port;

    @Autowired
    private org.springframework.core.env.Environment environment;

    private WebTestClient client() {
        return WebTestClient.bindToServer().baseUrl("http://127.0.0.1:" + port).build();
    }

    @Test
    void theRealConnectionFromTheAlbIsAcceptedEvenWithTheClientIpInXForwardedFor() {
        // Petición de un conductor reenviada por el ALB: el ALB agrega la IP pública del teléfono.
        HttpStatus status = (HttpStatus) client().get().uri("/ruta-inexistente")
                .header("X-Forwarded-For", "190.27.31.93")
                .exchange().returnResult(String.class).getStatus();

        assertThat(status).as("pasa el filtro de origen (404 de ruta, no 403)").isNotEqualTo(HttpStatus.FORBIDDEN);
        assertThat(environment.getProperty("server.forward-headers-strategy")).isEqualTo("none");
    }

    @Test
    void aForgedXForwardedForDoesNotGrantAccessToAnUntrustedConnection() {
        // Lo contrario: un cliente no puede colarse inventando X-Forwarded-For con una IP de la lista.
        TrustedSourceFilter onlyTenNet = new TrustedSourceFilter("10.0.0.0/8");
        org.springframework.mock.web.server.MockServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(
                        org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("/api/v1/loads")
                                .remoteAddress(new java.net.InetSocketAddress("190.27.31.93", 40000))
                                .header("X-Forwarded-For", "10.1.2.3"));

        onlyTenNet.filter(exchange, ignored -> reactor.core.publisher.Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
}
