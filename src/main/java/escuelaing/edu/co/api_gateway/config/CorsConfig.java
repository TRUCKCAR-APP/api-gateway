package escuelaing.edu.co.api_gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * CORS de la API: el gateway es el único responsable (las rutas HTTP no reenvían Origin a los servicios).
 * <p>
 * Orígenes en gateway.cors.allowed-origins ← TRUCKCAR_CORS_ALLOWED_ORIGINS (lista separada por comas, sin barra final).
 * El valor por defecto (http://localhost:*, http://127.0.0.1:*) solo sirve para mvnw spring-boot:run con Live Server;
 * docker-compose pasa los orígenes exactos de la PWA (:5500) y Kubernetes el dominio real.
 * <p>
 * Con el perfil prod (k8s), un origen con comodín, localhost o 127.0.0.1 detiene el arranque (KAN-33): con
 * allowCredentials=true, un patrón así deja que cualquier página servida en esa máquina use la sesión del usuario.
 */
@Configuration
public class CorsConfig {

    static final String PROD_PROFILE = "prod";

    private static final Logger log = LoggerFactory.getLogger(CorsConfig.class);

    private final List<String> allowedOrigins;

    public CorsConfig(@Value("${gateway.cors.allowed-origins}") String allowedOrigins, Environment environment) {
        this.allowedOrigins = parse(allowedOrigins);
        if (environment.acceptsProfiles(Profiles.of(PROD_PROFILE))) {
            validateForProduction(this.allowedOrigins);
        }
        log.info("CORS: orígenes permitidos {}", this.allowedOrigins);
    }

    static List<String> parse(String origins) {
        return Arrays.stream(origins == null ? new String[0] : origins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isBlank())
                .toList();
    }

    /** Lanza IllegalStateException si la lista no es apta para producción; el mensaje queda en el log de arranque. */
    static void validateForProduction(List<String> origins) {
        if (origins.isEmpty()) {
            throw new IllegalStateException("CORS de producción: TRUCKCAR_CORS_ALLOWED_ORIGINS está vacío; defina el"
                    + " dominio de la PWA (p. ej. https://app.truckcar.co)");
        }
        for (String origin : origins) {
            String lower = origin.toLowerCase(Locale.ROOT);
            if (lower.contains("*") || lower.contains("localhost") || lower.contains("127.0.0.1")
                    || lower.contains("[::1]")) {
                throw new IllegalStateException("CORS de producción no admite comodines ni localhost: '" + origin
                        + "' en TRUCKCAR_CORS_ALLOWED_ORIGINS. Use el dominio exacto de la PWA (p. ej."
                        + " https://app.truckcar.co)");
            }
        }
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOriginPatterns(allowedOrigins);
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // Sin X-Auth-*: solo el gateway escribe la identidad; el navegador nunca debe poder enviarla.
        corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept", "X-Correlation-Id"));
        // Retry-After y X-RateLimit-*: la PWA los lee al recibir un 429 del límite de intentos de /api/v1/auth.
        corsConfig.setExposedHeaders(Arrays.asList("X-Correlation-Id", "Retry-After", "X-RateLimit-Remaining",
                "X-RateLimit-Replenish-Rate", "X-RateLimit-Burst-Capacity", "X-RateLimit-Requested-Tokens"));
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }
}
