package escuelaing.edu.co.api_gateway.loadbalancer;

import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Configuración por cliente de Spring Cloud LoadBalancer (no es @Configuration: la aplica
 * {@link LoadBalancerConfig} en el contexto hijo de cada servicio). El nombre DNS es el serviceId de la ruta
 * lb://&lt;serviceId&gt; y el puerto sale de truckcar.loadbalancer.ports.&lt;serviceId&gt;.
 * El balanceador por defecto es round-robin.
 */
public class DnsLoadBalancerConfiguration {

    @Bean
    public ServiceInstanceListSupplier dnsServiceInstanceListSupplier(Environment environment) {
        String serviceId = environment.getRequiredProperty(LoadBalancerClientFactory.PROPERTY_NAME);
        int port = environment.getRequiredProperty("truckcar.loadbalancer.ports." + serviceId, Integer.class);
        return new DnsServiceInstanceListSupplier(serviceId, serviceId, port);
    }
}
