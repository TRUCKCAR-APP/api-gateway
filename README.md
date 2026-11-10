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
| Servicio destino caído / Redis caído al canjear el ticket | 503 |
| Servicio destino sin respuesta a tiempo | 504 |

Las respuestas de error de los microservicios se reenvían tal cual.

## Variables de entorno

| Variable | Descripción |
|---|---|
| `TRUCKCAR_JWT_SECRET` | **Obligatoria.** Secreto JWT en Base64 (>= 256 bits), el mismo de User-Identity y Notifications. Sin él el gateway no arranca. |
| `JWT_SECRET` | Nombre heredado del secreto; solo se usa si `TRUCKCAR_JWT_SECRET` no está definido. |
| `TRUCKCAR_CORS_ALLOWED_ORIGINS` | Orígenes permitidos en producción (en local se acepta cualquier puerto de `localhost`). |
| `TRUCKCAR_GATEWAY_TRUSTED_SOURCE_CIDRS` | CIDR separados por coma desde los que se aceptan conexiones (en AWS, **las subredes del ALB**). Se compara la IP de la conexión TCP, nunca `X-Forwarded-For`. Cualquier otro origen recibe 403. Vacío = sin restricción (Docker/local). `/actuator/**` (puerto de gestión 8090) queda fuera para probes y Prometheus. |
| `TRUCKCAR_*_URL` | URL de cada microservicio (ver `src/main/resources/application.yaml`). |

## Ejecución local

```bash
export TRUCKCAR_JWT_SECRET="<mismo valor que en User-Identity>"
./mvnw spring-boot:run
```
