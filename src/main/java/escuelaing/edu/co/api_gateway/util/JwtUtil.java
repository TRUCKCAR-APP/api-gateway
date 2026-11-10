package escuelaing.edu.co.api_gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Optional;
import java.util.Set;

@Component
public class JwtUtil {

    /** Roles que emite User-Identity (enum Role). */
    public static final Set<String> USER_ROLES = Set.of("CONDUCTOR", "COORDINADOR", "GENERADOR", "ADMIN");
    /** Un access token real ocupa unos cientos de bytes; uno enorme no se intenta parsear. */
    private static final int MAX_TOKEN_LENGTH = 8192;

    private final SecretKey key;

    public JwtUtil(@Value("${app.jwt.secret}") String secret) {
        try {
            this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "TRUCKCAR_JWT_SECRET debe ser un valor Base64 de al menos 256 bits, igual al de User-Identity", e);
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(this.key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenValid(String token) {
        return validClaims(token).isPresent();
    }

    /**
     * Claims de un access token aceptable, o vacío si no lo es. Además de la firma HMAC exige:
     * <ul>
     *   <li>vencimiento ({@code exp}): User-Identity siempre lo emite; un token sin él no caducaría nunca;</li>
     *   <li>sujeto ({@code sub}) no vacío: es el X-Auth-User que reciben los servicios;</li>
     *   <li>un rol de usuario conocido: SYSTEM (o cualquier otro) solo lo usan las llamadas internas y nunca puede
     *       llegar desde fuera en un JWT.</li>
     * </ul>
     */
    public Optional<Claims> validClaims(String token) {
        if (token == null || token.isBlank() || token.length() > MAX_TOKEN_LENGTH) {
            return Optional.empty();
        }
        try {
            Claims claims = getClaims(token); // firma y exp (jjwt rechaza un token vencido o sin firma)
            if (claims.getExpiration() == null) {
                return Optional.empty();
            }
            String subject = claims.getSubject();
            Object role = claims.get("role");
            if (subject == null || subject.isBlank() || role == null || !USER_ROLES.contains(role.toString())) {
                return Optional.empty();
            }
            return Optional.of(claims);
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}