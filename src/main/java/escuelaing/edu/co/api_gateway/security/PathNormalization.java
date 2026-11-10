package escuelaing.edu.co.api_gateway.security;

import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;

/**
 * La ruta tal como la interpreta un servicio Spring detrás del gateway: decodificada, sin barras dobles, con los
 * segmentos "." y ".." resueltos, sin parámetros ";..." y en minúsculas. Las reglas de acceso del gateway que dependen
 * de la ruta (solo ADMIN en /api/v1/templates, rutas canónicas en /api/v1/auth) deben decidir sobre esta forma: si
 * comparan el texto crudo, /api/v1/notifications/../templates las esquiva y el servicio lo atiende como
 * /api/v1/templates.
 */
public final class PathNormalization {

    private PathNormalization() {
    }

    public static String normalize(String rawPath) {
        if (rawPath == null) {
            return "/";
        }
        String decoded;
        try {
            decoded = UriUtils.decode(rawPath, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            decoded = rawPath;   // % mal formado: se evalúa tal cual
        }
        Deque<String> segments = new ArrayDeque<>();
        for (String segment : decoded.replace('\\', '/').split("/")) {
            int matrix = segment.indexOf(';');
            String clean = matrix >= 0 ? segment.substring(0, matrix) : segment;
            if (clean.isEmpty() || clean.equals(".")) {
                continue;
            }
            if (clean.equals("..")) {
                segments.pollLast();
            } else {
                segments.addLast(clean);
            }
        }
        return ("/" + String.join("/", segments)).toLowerCase(Locale.ROOT);
    }

    /** ¿La ruta normalizada es prefix o está debajo de prefix? (prefix en minúsculas, sin barra final). */
    public static boolean isUnder(String rawPath, String prefix) {
        String normalized = normalize(rawPath);
        return normalized.equals(prefix) || normalized.startsWith(prefix + "/");
    }
}
