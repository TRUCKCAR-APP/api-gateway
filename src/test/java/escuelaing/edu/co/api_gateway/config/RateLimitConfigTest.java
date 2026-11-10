package escuelaing.edu.co.api_gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.net.InetSocketAddress;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/** IP del cliente para el límite de intentos: nunca la que el cliente escriba en X-Forwarded-For. */
class RateLimitConfigTest {

    private static MockServerHttpRequest from(String remoteIp, String forwardedFor) {
        MockServerHttpRequest.BaseBuilder<?> builder = MockServerHttpRequest.post("/api/v1/auth/login")
                .remoteAddress(new InetSocketAddress(remoteIp, 40000));
        if (forwardedFor != null) {
            builder.header("X-Forwarded-For", forwardedFor);
        }
        return builder.build();
    }

    @Test
    void withoutTrustTheTcpAddressIsUsedAndForwardedForIsIgnored() {
        assertThat(RateLimitConfig.clientIp(from("172.23.0.1", "1.2.3.4"), false, 1)).isEqualTo("172.23.0.1");
        assertThat(RateLimitConfig.clientIp(from("172.23.0.1", null), false, 1)).isEqualTo("172.23.0.1");
    }

    @Test
    void behindTheAlbTheEntryAddedByTheAlbIsUsedNotTheOneTheClientWrote() {
        // El cliente envía "X-Forwarded-For: 6.6.6.6" para estrenar un cubo; el ALB agrega su IP real al final.
        assertThat(RateLimitConfig.clientIp(from("10.0.1.20", "6.6.6.6, 181.50.3.7"), true, 1)).isEqualTo("181.50.3.7");
        assertThat(RateLimitConfig.clientIp(from("10.0.1.20", "181.50.3.7"), true, 1)).isEqualTo("181.50.3.7");
    }

    @Test
    void withTwoTrustedProxiesTheSecondFromTheRightIsTheClient() {
        // Cloudflare agrega la IP del cliente; el ALB, la del conector de Cloudflare.
        assertThat(RateLimitConfig.clientIp(from("10.0.1.20", "6.6.6.6, 181.50.3.7, 172.68.10.1"), true, 2))
                .isEqualTo("181.50.3.7");
        // Menos entradas que proxies: la más a la izquierda, nunca un índice fuera de rango.
        assertThat(RateLimitConfig.clientIp(from("10.0.1.20", "181.50.3.7"), true, 2)).isEqualTo("181.50.3.7");
    }

    @Test
    void trustedButMissingOrBlankForwardedForFallsBackToTheTcpAddress() {
        assertThat(RateLimitConfig.clientIp(from("10.0.1.20", null), true, 1)).isEqualTo("10.0.1.20");
        assertThat(RateLimitConfig.clientIp(from("10.0.1.20", " , "), true, 1)).isEqualTo("10.0.1.20");
    }

    @Test
    void withoutAnyAddressTheKeyIsUnknownNeverEmpty() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/v1/auth/login").build();
        assertThat(RateLimitConfig.clientIp(request, false, 1)).isEqualTo(RateLimitConfig.UNKNOWN_CLIENT);
    }

    @Test
    void theKeyIncludesTheRouteSoLoginAndRegisterHaveSeparateBuckets() {
        KeyResolver resolver = new RateLimitConfig().clientIpKeyResolver(false, 1);
        MockServerWebExchange login = MockServerWebExchange.from(from("172.23.0.1", null));
        login.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, route("user-identity-login-route"));
        MockServerWebExchange register = MockServerWebExchange.from(from("172.23.0.1", null));
        register.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, route("user-identity-auth-route"));

        assertThat(resolver.resolve(login).block()).isEqualTo("auth:user-identity-login-route:172.23.0.1");
        assertThat(resolver.resolve(register).block()).isEqualTo("auth:user-identity-auth-route:172.23.0.1");
    }

    private static Route route(String id) {
        return Route.async().id(id).uri(URI.create("http://localhost:8080")).predicate(exchange -> true).build();
    }
}
