package escuelaing.edu.co.api_gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TrustedSourceFilterTest {

    private static boolean[] run(TrustedSourceFilter filter, String path, String remoteIp, String forwardedFor) {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get(path)
                .remoteAddress(new InetSocketAddress(remoteIp, 40000));
        if (forwardedFor != null) {
            request.header("X-Forwarded-For", forwardedFor);
        }
        MockServerWebExchange exchange = MockServerWebExchange.from(request.build());
        boolean[] passed = {false};
        WebFilterChain chain = ex -> {
            passed[0] = true;
            return Mono.empty();
        };
        filter.filter(exchange, chain).block();
        if (!passed[0]) {
            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(exchange.getResponse().getBodyAsString().block()).contains("balanceador de carga");
        }
        return passed;
    }

    @Test
    void onlyConnectionsFromTheAlbSubnetsPass() {
        TrustedSourceFilter filter = new TrustedSourceFilter("192.168.0.0/19, 192.168.32.0/19");

        assertThat(run(filter, "/api/v1/loads", "192.168.10.7", null)[0]).isTrue();
        assertThat(run(filter, "/api/v1/loads", "192.168.40.1", null)[0]).isTrue();
        assertThat(run(filter, "/api/v1/loads", "192.168.96.15", null)[0]).isFalse(); // subred de pods/nodos
        assertThat(run(filter, "/api/v1/loads", "8.8.8.8", null)[0]).isFalse();
    }

    @Test
    void xForwardedForCannotBeUsedToImpersonateTheAlb() {
        TrustedSourceFilter filter = new TrustedSourceFilter("10.0.0.0/24");

        assertThat(run(filter, "/api/v1/loads", "203.0.113.9", "10.0.0.5")[0]).isFalse();
    }

    @Test
    void ipv4MappedAddressesAndIpv6BlocksAreSupported() {
        TrustedSourceFilter filter = new TrustedSourceFilter("10.0.0.0/8,2600:1f18::/32");

        assertThat(run(filter, "/api/v1/loads", "::ffff:10.1.2.3", null)[0]).isTrue();
        assertThat(run(filter, "/api/v1/loads", "2600:1f18:abcd::1", null)[0]).isTrue();
        assertThat(run(filter, "/api/v1/loads", "2600:1f19::1", null)[0]).isFalse();
    }

    @Test
    void emptyListAllowsEverythingForLocalDevelopment() {
        assertThat(run(new TrustedSourceFilter(""), "/api/v1/loads", "8.8.8.8", null)[0]).isTrue();
    }

    @Test
    void actuatorProbesAreExemptButNotAsATraversalBridge() {
        TrustedSourceFilter filter = new TrustedSourceFilter("10.0.0.0/24");

        assertThat(run(filter, "/actuator/health/liveness", "172.16.0.9", null)[0]).isTrue();
        assertThat(run(filter, "/actuator/../api/v1/loads", "172.16.0.9", null)[0]).isFalse();
        assertThat(run(filter, "/actuator/%2e%2e/api/v1/loads", "172.16.0.9", null)[0]).isFalse();
    }

    @Test
    void malformedCidrFailsAtStartup() {
        assertThatThrownBy(() -> new TrustedSourceFilter("10.0.0.0/33")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TrustedSourceFilter("alb.example.com/24")).isInstanceOf(IllegalArgumentException.class);
    }
}
