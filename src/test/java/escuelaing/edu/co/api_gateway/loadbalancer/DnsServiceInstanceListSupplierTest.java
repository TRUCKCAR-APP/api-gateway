package escuelaing.edu.co.api_gateway.loadbalancer;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.client.ServiceInstance;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DnsServiceInstanceListSupplierTest {

    @Test
    void resolvesEveryAddressOfTheServiceNameAsAnInstance() {
        DnsServiceInstanceListSupplier supplier = new DnsServiceInstanceListSupplier("fleets-drivers", "localhost", 8081);

        List<ServiceInstance> instances = supplier.get().blockFirst();

        assertThat(instances).isNotEmpty();
        assertThat(instances).allSatisfy(instance -> {
            assertThat(instance.getServiceId()).isEqualTo("fleets-drivers");
            assertThat(instance.getPort()).isEqualTo(8081);
            assertThat(instance.getUri().getScheme()).isEqualTo("http");
        });
    }

    @Test
    void unknownHostYieldsNoInstancesInsteadOfFailing() {
        DnsServiceInstanceListSupplier supplier =
                new DnsServiceInstanceListSupplier("fleets-drivers", "no-existe.invalid", 8081);

        assertThat(supplier.get().blockFirst()).isEmpty();
    }
}
