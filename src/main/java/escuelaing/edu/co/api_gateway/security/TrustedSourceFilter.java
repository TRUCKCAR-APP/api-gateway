package escuelaing.edu.co.api_gateway.security;

import escuelaing.edu.co.api_gateway.error.GatewayErrors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * Solo el balanceador (ALB) puede hablar con el gateway. Se compara la dirección de la conexión TCP (la del ALB con
 * target-type ip), nunca X-Forwarded-For, que el cliente puede inventar. La lista llega en
 * TRUCKCAR_GATEWAY_TRUSTED_SOURCE_CIDRS (CIDR separados por coma: las subredes del ALB). Vacía = sin restricción, para
 * Docker y desarrollo local, donde no hay ALB.
 * <p>
 * Es una segunda barrera además de la NetworkPolicy y el security group: si alguno se abre por error (o la VPC
 * comparte CIDR con los nodos), el gateway sigue rechazando el tráfico que no viene del ALB con 403.
 * <p>
 * /actuator/** queda fuera: lo sirve el puerto de gestión (8090, no expuesto por el ALB) a los probes del kubelet y a
 * Prometheus; en :8000 esas rutas no se enrutan.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TrustedSourceFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(TrustedSourceFilter.class);

    private final List<Cidr> trusted;

    public TrustedSourceFilter(@Value("${gateway.trusted-source-cidrs:}") String cidrs) {
        this.trusted = Arrays.stream(cidrs.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .map(Cidr::parse)
                .toList();
        if (trusted.isEmpty()) {
            log.warn("gateway.trusted-source-cidrs vacío: el gateway acepta conexiones de cualquier origen"
                    + " (defina TRUCKCAR_GATEWAY_TRUSTED_SOURCE_CIDRS con las subredes del ALB en producción)");
        } else {
            log.info("El gateway solo acepta conexiones desde {}", trusted);
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        boolean actuator = path.startsWith("/actuator/") && !path.contains("..") && !path.contains("%");
        if (trusted.isEmpty() || actuator) {
            return chain.filter(exchange);
        }
        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        InetAddress address = remote == null ? null : remote.getAddress();
        if (address != null && trusted.stream().anyMatch(cidr -> cidr.contains(address))) {
            return chain.filter(exchange);
        }
        log.warn("Conexión rechazada: {} no está entre los orígenes permitidos ({} {})",
                address == null ? "origen desconocido" : address.getHostAddress(),
                exchange.getRequest().getMethod(), exchange.getRequest().getPath());
        return GatewayErrors.write(exchange, HttpStatus.FORBIDDEN, "Acceso denegado",
                "Solo se admite tráfico a través del balanceador de carga de TruckCar");
    }

    /** Bloque CIDR IPv4 o IPv6 ("10.0.0.0/16", "2600:1f18::/56"; una IP sola equivale a /32 o /128). */
    record Cidr(byte[] network, int prefix, String text) {

        static Cidr parse(String value) {
            String[] parts = value.split("/", 2);
            try {
                byte[] address = InetAddress.getByName(literal(parts[0])).getAddress();
                int prefix = parts.length == 2 ? Integer.parseInt(parts[1]) : address.length * 8;
                if (prefix < 0 || prefix > address.length * 8) {
                    throw new IllegalArgumentException("Prefijo fuera de rango en " + value);
                }
                return new Cidr(address, prefix, value);
            } catch (UnknownHostException | NumberFormatException e) {
                throw new IllegalArgumentException("CIDR inválido en gateway.trusted-source-cidrs: " + value, e);
            }
        }

        /** Solo literales IP: un nombre de host haría una consulta DNS al arrancar y no es un CIDR. */
        private static String literal(String host) {
            if (!host.matches("[0-9a-fA-F:.]+")) {
                throw new IllegalArgumentException("CIDR inválido en gateway.trusted-source-cidrs: " + host);
            }
            return host;
        }

        boolean contains(InetAddress candidate) {
            byte[] bytes = candidate.getAddress();
            if (bytes.length != network.length) {
                // IPv4 mapeada en IPv6 (::ffff:a.b.c.d) contra un bloque IPv4.
                if (bytes.length == 16 && network.length == 4 && isMappedIpv4(bytes)) {
                    bytes = Arrays.copyOfRange(bytes, 12, 16);
                } else {
                    return false;
                }
            }
            int fullBytes = prefix / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (bytes[i] != network[i]) {
                    return false;
                }
            }
            int remainingBits = prefix % 8;
            if (remainingBits == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remainingBits) & 0xFF;
            return (bytes[fullBytes] & mask) == (network[fullBytes] & mask);
        }

        private static boolean isMappedIpv4(byte[] bytes) {
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    return false;
                }
            }
            return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
        }

        @Override
        public String toString() {
            return text;
        }
    }
}
