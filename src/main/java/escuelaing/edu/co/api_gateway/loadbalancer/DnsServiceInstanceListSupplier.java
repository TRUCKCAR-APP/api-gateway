package escuelaing.edu.co.api_gateway.loadbalancer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.client.DefaultServiceInstance;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * Instancias de un servicio a partir de todos los registros A de su nombre DNS. En Docker Compose el nombre del
 * servicio (fleets-drivers) resuelve a la IP de cada réplica de --scale, y en Kubernetes un Service headless hace lo
 * mismo, así que no hace falta un registro de servicios (Eureka/Consul). Se resuelve en cada selección: la caché de
 * DNS de la JVM (30 s) limita el costo y una réplica nueva entra al balanceo en ese plazo.
 */
public class DnsServiceInstanceListSupplier implements ServiceInstanceListSupplier {

    private static final Logger log = LoggerFactory.getLogger(DnsServiceInstanceListSupplier.class);

    private final String serviceId;
    private final String host;
    private final int port;

    public DnsServiceInstanceListSupplier(String serviceId, String host, int port) {
        this.serviceId = serviceId;
        this.host = host;
        this.port = port;
    }

    @Override
    public String getServiceId() {
        return serviceId;
    }

    @Override
    public Flux<List<ServiceInstance>> get() {
        // getAllByName bloquea: se resuelve fuera del event loop de Netty.
        return Mono.fromCallable(this::resolve).subscribeOn(Schedulers.boundedElastic()).flux();
    }

    List<ServiceInstance> resolve() {
        try {
            return Arrays.stream(InetAddress.getAllByName(host))
                    .map(InetAddress::getHostAddress)
                    .distinct()
                    .map(ip -> (ServiceInstance) new DefaultServiceInstance(serviceId + "-" + ip, serviceId, ip, port, false))
                    .toList();
        } catch (UnknownHostException e) {
            // Sin instancias el balanceador responde 503: el servicio está caído, no hay a quién reenviar.
            log.warn("No se pudo resolver {} para el servicio {}: {}", host, serviceId, e.getMessage());
            return List.of();
        }
    }
}
