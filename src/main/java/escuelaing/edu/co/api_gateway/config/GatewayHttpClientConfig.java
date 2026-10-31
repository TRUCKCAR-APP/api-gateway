package escuelaing.edu.co.api_gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.config.HttpClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Caché de DNS del cliente HTTP del gateway (Reactor Netty). Por defecto respeta el TTL que entrega el DNS: en Docker
 * son 600 s, así que al recrear un servicio (nueva IP) el gateway seguía enviando a la IP vieja ("Connection
 * refused") hasta 10 minutos. Con un TTL máximo corto las rutas siguen al contenedor nuevo en segundos.
 */
@Configuration
public class GatewayHttpClientConfig {

    @Bean
    public HttpClientCustomizer dnsCacheCustomizer(
            @Value("${truckcar.gateway.dns-cache-max-ttl:10s}") Duration maxTtl,
            @Value("${truckcar.gateway.dns-cache-negative-ttl:2s}") Duration negativeTtl) {
        return httpClient -> httpClient.resolver(spec -> spec
                .cacheMaxTimeToLive(maxTtl)
                .cacheNegativeTimeToLive(negativeTtl));
    }
}
