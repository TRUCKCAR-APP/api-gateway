package escuelaing.edu.co.api_gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Origin solo se retira en las rutas HTTP. La ruta WebSocket lo conserva: sin él, el cliente WebSocket de Netty envía
 * uno con la URL del pod y fleets-drivers rechaza el handshake (en EKS la torre de control quedaba "Reconectando").
 */
@SpringBootTest
@TestPropertySource(properties = {
        "app.jwt.secret=dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI="
})
class GatewayOriginRoutingTest {

    private static final String WS_ROUTE = "fleets-drivers-telemetry-ws";

    @Autowired
    private GatewayProperties gateway;

    @Test
    void noDefaultFilterRemovesOrigin() {
        assertThat(gateway.getDefaultFilters()).noneMatch(GatewayOriginRoutingTest::removesOrigin);
    }

    @Test
    void theWebSocketRouteKeepsTheBrowserOrigin() {
        RouteDefinition ws = gateway.getRoutes().stream().filter(r -> r.getId().equals(WS_ROUTE)).findFirst().orElseThrow();
        assertThat(ws.getFilters()).noneMatch(GatewayOriginRoutingTest::removesOrigin);
    }

    @Test
    void everyHttpRouteRemovesOrigin() {
        List<RouteDefinition> http = gateway.getRoutes().stream().filter(r -> !r.getId().equals(WS_ROUTE)).toList();
        assertThat(http).isNotEmpty().allSatisfy(route ->
                assertThat(route.getFilters()).as(route.getId()).anyMatch(GatewayOriginRoutingTest::removesOrigin));
    }

    private static boolean removesOrigin(FilterDefinition filter) {
        return filter.getName().equals("RemoveRequestHeader") && filter.getArgs().containsValue("Origin");
    }
}
