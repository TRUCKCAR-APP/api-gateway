package escuelaing.edu.co.api_gateway.loadbalancer;

import org.springframework.cloud.loadbalancer.annotation.LoadBalancerClients;
import org.springframework.context.annotation.Configuration;

/** Toda ruta lb://&lt;servicio&gt; obtiene sus instancias por DNS (DnsLoadBalancerConfiguration). */
@Configuration
@LoadBalancerClients(defaultConfiguration = DnsLoadBalancerConfiguration.class)
public class LoadBalancerConfig {
}
