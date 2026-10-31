package escuelaing.edu.co.api_gateway.config;

import io.micrometer.observation.ObservationPredicate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.observation.ServerRequestObservationContext;

@Configuration
public class ObservabilityConfig {

    /** Sin trazas para el scrape de Prometheus ni los health checks del puerto de gestión. */
    @Bean
    ObservationPredicate skipActuatorObservations() {
        return (name, context) -> !(context instanceof ServerRequestObservationContext request)
                || !request.getCarrier().getPath().value().startsWith("/actuator");
    }
}
