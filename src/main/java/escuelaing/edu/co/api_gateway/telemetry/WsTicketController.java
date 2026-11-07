package escuelaing.edu.co.api_gateway.telemetry;

import escuelaing.edu.co.api_gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;

import escuelaing.edu.co.api_gateway.error.GatewayErrors;
import org.springframework.web.server.ServerWebExchange;

/**
 * POST /api/v1/telemetry/ws-ticket con el JWT en Authorization: devuelve el ticket con el que la PWA abre
 * /ws-telemetry?ticket=... El gateway lo atiende él mismo (no es una ruta hacia un servicio), por eso valida aquí el
 * JWT en lugar de en JwtAuthenticationFilter, que solo filtra las peticiones enrutadas.
 */
@RestController
public class WsTicketController {

    private static final Logger log = LoggerFactory.getLogger(WsTicketController.class);

    public static final String PATH = "/api/v1/telemetry/ws-ticket";

    private final JwtUtil jwtUtil;
    private final WsTicketStore tickets;

    public WsTicketController(JwtUtil jwtUtil, WsTicketStore tickets) {
        this.jwtUtil = jwtUtil;
        this.tickets = tickets;
    }

    @PostMapping(PATH)
    public Mono<ResponseEntity<Map<String, Object>>> issue(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            ServerWebExchange exchange) {
        String token = authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)
                ? authorization.substring(7).trim() : null;
        Optional<Claims> claims = token == null ? Optional.empty() : jwtUtil.validClaims(token);
        if (claims.isEmpty()) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                    .cacheControl(CacheControl.noStore())
                    .body(GatewayErrors.body(HttpStatus.UNAUTHORIZED, "No autenticado", token == null
                            ? "Se requiere el token de acceso en la cabecera Authorization: Bearer <token>"
                            : "El token de acceso no es válido o ya venció; inicie sesión de nuevo", exchange)));
        }
        Object role = claims.get().get("role");
        return tickets.issue(claims.get().getSubject(), role == null ? "" : role.toString())
                .map(ticket -> ResponseEntity.ok()
                        .cacheControl(CacheControl.noStore())
                        .body(Map.<String, Object>of("ticket", ticket, "expiresInSeconds", tickets.ttl().toSeconds())))
                .onErrorResume(e -> {
                    log.warn("No se pudo emitir el ticket del WebSocket: {}", e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                            .cacheControl(CacheControl.noStore())
                            .body(GatewayErrors.body(HttpStatus.SERVICE_UNAVAILABLE, "Servicio no disponible",
                                    "No se pudo emitir el ticket del WebSocket; intente de nuevo en unos segundos",
                                    exchange)));
                });
    }
}
