# api-gateway

Punto de entrada único de TruckCar (puerto `8000`). Valida el JWT emitido por User-Identity, enruta a los
microservicios y propaga la identidad del usuario en headers internos.

## Headers propagados

| Header | Origen |
|---|---|
| `X-Auth-User` | `sub` del token (id del usuario) |
| `X-Auth-Role` | claim `role` del token (`CONDUCTOR`, `COORDINADOR`, `ADMIN`) |
| `X-Correlation-Id` | El recibido del cliente o uno nuevo |

Los valores de `X-Auth-User` y `X-Auth-Role` enviados por el cliente se descartan siempre, también en las rutas
públicas: solo el gateway puede fijarlos.

## Autenticación

- **JWT** en `Authorization: Bearer <token>`. Se exige firma HMAC válida, `exp`, `sub` no vacío y un rol de usuario
  (`CONDUCTOR`, `COORDINADOR`, `GENERADOR`, `ADMIN`). Un rol interno como `SYSTEM` nunca se acepta desde fuera.
- **Rutas abiertas**: `/api/v1/auth/**`, `/actuator/health` y `GET /api/v1/loads/public-tracking/{token}` (enlace firmado
  que valida Load-Allocation).
- **WebSocket `/ws-telemetry`**: el navegador pide `POST /api/v1/telemetry/ws-ticket` con su JWT y abre el socket con
  `?ticket=`. El ticket vive 30 s en Redis y se borra al primer uso (GETDEL). Un JWT en la URL (`?access_token=`) nunca
  autentica y se elimina antes de reenviar.

## Errores

Todo error que produce el propio gateway sale con el mismo JSON que usan los microservicios:

```json
{"timestamp":"2026-11-06T18:00:00Z","status":401,"error":"No autenticado",
 "message":"Se requiere autenticación: envíe el token en la cabecera Authorization: Bearer <token>",
 "path":"/api/v1/loads","correlationId":"6f0c..."}
```

| Caso | Estado |
|---|---|
| Sin token, token inválido/vencido, ticket usado o vencido | 401 |
| Conexión que no viene del ALB (`TRUCKCAR_GATEWAY_TRUSTED_SOURCE_CIDRS`) | 403 |
| Ruta inexistente | 404 |
| Demasiados intentos en `/api/v1/auth/login`, `/register` o `/refresh` | 429 |
| Servicio destino caído / Redis caído al canjear el ticket | 503 |
| Servicio destino sin respuesta a tiempo | 504 |

Las respuestas de error de los microservicios se reenvían tal cual.

## Límite de intentos en `/api/v1/auth` (KAN-31)

Frena la fuerza bruta y el *credential stuffing* con el `RequestRateLimiter` de Spring Cloud Gateway: un token bucket
por IP del cliente en Redis, compartido por todas las réplicas.

| Ruta | Límite por defecto | Variables |
|---|---|---|
| `POST /api/v1/auth/login` (`user-identity-login-route`) | 1 intento/s, ráfaga de 5 | `TRUCKCAR_RATE_LIMIT_LOGIN_REPLENISH_RATE`, `TRUCKCAR_RATE_LIMIT_LOGIN_BURST_CAPACITY` |
| `/api/v1/auth/register` y `/refresh` (`user-identity-auth-route`) | 5/s, ráfaga de 10 | `TRUCKCAR_RATE_LIMIT_AUTH_REPLENISH_RATE`, `TRUCKCAR_RATE_LIMIT_AUTH_BURST_CAPACITY` |
| Resto de `/api/v1/auth/**` y `/api/v1/users/**` | sin límite | — |

- **Respuesta:** `429` con el JSON de errores (`"message":"Demasiados intentos, espere unos segundos"`), `Retry-After` y
  `X-RateLimit-Remaining`, `-Replenish-Rate`, `-Burst-Capacity` y `-Requested-Tokens`, expuestas por CORS para la PWA.
- **IP del cliente** (`RateLimitConfig`): en Docker/local, la de la conexión TCP; `X-Forwarded-For` se ignora porque el
  cliente puede inventarlo. Detrás de un proxy (`TRUCKCAR_RATE_LIMIT_TRUST_FORWARDED_FOR=true`, como en k8s), la entrada
  que agregó el proxy, contando `TRUCKCAR_RATE_LIMIT_TRUSTED_PROXIES` desde la derecha (1 = ALB; 2 = Cloudflare + ALB).
- **Claves en Redis:** `request_rate_limiter.{auth:<ruta>:<ip>}.tokens` y `.timestamp`, con TTL. Cada ruta tiene su cubo.
- **Sin Redis (fail-open):** el limitador deja pasar las peticiones; el login sigue funcionando, sin protección. Cada una
  suma en `truckcar_gateway_rate_limiter_fail_open_total` (alerta `TruckCarAuthRateLimiterFailOpen`) y queda un `WARN` en
  el log. `spring.data.redis.timeout` (2 s) evita que cada login espere 60 s a Redis.
- **Fuerza bruta en curso:** alerta `TruckCarAuthBruteForceSuspected` sobre `spring_cloud_gateway_requests_seconds_count`
  con `httpStatusCode="429"` en las dos rutas.

Prueba: `RateLimitRouteTest` (Redis real con Testcontainers; requiere Docker).

## Variables de entorno

| Variable | Descripción |
|---|---|
| `TRUCKCAR_JWT_SECRET` | **Obligatoria.** Secreto JWT en Base64 (>= 256 bits), el mismo de User-Identity y Notifications. Sin él el gateway no arranca. |
| `JWT_SECRET` | Nombre heredado del secreto; solo se usa si `TRUCKCAR_JWT_SECRET` no está definido. |
| `TRUCKCAR_CORS_ALLOWED_ORIGINS` | Orígenes permitidos en producción (en local se acepta cualquier puerto de `localhost`). |
| `TRUCKCAR_GATEWAY_TRUSTED_SOURCE_CIDRS` | CIDR separados por coma desde los que se aceptan conexiones (en AWS, **las subredes del ALB**). Se compara la IP de la conexión TCP, nunca `X-Forwarded-For`. Cualquier otro origen recibe 403. Vacío = sin restricción (Docker/local). `/actuator/**` (puerto de gestión 8090) queda fuera para probes y Prometheus. |
| `TRUCKCAR_RATE_LIMIT_TRUST_FORWARDED_FOR` | `true` detrás de un proxy (k8s): la IP del cliente sale de `X-Forwarded-For`. Por defecto `false` (la IP de la conexión). |
| `TRUCKCAR_RATE_LIMIT_TRUSTED_PROXIES` | Proxies de confianza delante del gateway (por defecto 1). |
| `TRUCKCAR_RATE_LIMIT_*_REPLENISH_RATE` / `_BURST_CAPACITY` | Límites de login y de register/refresh (ver arriba). |
| `SPRING_DATA_REDIS_TIMEOUT` | Timeout de los comandos a Redis (por defecto `2s`). |
| `TRUCKCAR_*_URL` | URL de cada microservicio (ver `src/main/resources/application.yaml`). |

## Ejecución local

```bash
export TRUCKCAR_JWT_SECRET="<mismo valor que en User-Identity>"
./mvnw spring-boot:run
```
