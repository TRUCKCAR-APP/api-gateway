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

## Variables de entorno

| Variable | Descripción |
|---|---|
| `TRUCKCAR_JWT_SECRET` | **Obligatoria.** Secreto JWT en Base64 (>= 256 bits), el mismo de User-Identity y Notifications. Sin él el gateway no arranca. |
| `JWT_SECRET` | Nombre heredado del secreto; solo se usa si `TRUCKCAR_JWT_SECRET` no está definido. |
| `TRUCKCAR_CORS_ALLOWED_ORIGINS` | Orígenes permitidos en producción (en local se acepta cualquier puerto de `localhost`). |
| `TRUCKCAR_*_URL` | URL de cada microservicio (ver `src/main/resources/application.yaml`). |

## Ejecución local

```bash
export TRUCKCAR_JWT_SECRET="<mismo valor que en User-Identity>"
./mvnw spring-boot:run
```
