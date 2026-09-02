# Security

## 1. Propósito y responsabilidades

Security es la plataforma responsable de autenticar identidades, administrar
asignaciones y emitir tokens. `Security.Auth.dll` permite que una API ASP.NET
Core valide esos tokens y exija permisos mediante `SecureAuth`.

| Componente | Responsabilidad |
| --- | --- |
| Permissions | Define sistemas, scopes, permisos, roles y sus relaciones |
| Security API | Autentica usuarios y sistemas, administra asignaciones y emite JWT |
| `Security.Auth.dll` | Valida el JWT recibido y autoriza endpoints |
| API consumidora | Declara la `customKey` y el permiso de cada operación |

La DLL no crea scopes, configura roles, asigna permisos ni emite tokens. Consume
los permisos efectivos incluidos en los claims del JWT (atributos del token).

La autenticación responde quién realiza la solicitud. La autorización responde
qué puede hacer esa identidad y sobre qué instancia puede hacerlo.

## 2. Validación de solicitudes

La DLL autentica el JWT validando firma RSA, issuer (sistema emisor), audiences
(sistemas destinatarios) y vigencia. Después publica sus claims en la identidad
estándar de ASP.NET Core:

```csharp
var blikonId = User.FindFirst("blikon_id")?.Value;
```

`SecureAuth` evalúa el sistema propietario, su audience, la `customKey` y los
permisos efectivos presentes en `scp`.

Para permisos del sistema consumidor:

```csharp
[SecureAuth("system", "spaces.read")]
```

```text
Sistema propietario: sistema consumidor configurado
customKey:           system
Permiso:             spaces.read
```

Para permisos propiedad de otro sistema:

```csharp
[SecureAuth(
    "developer-system",
    "dev-account.{accountId}",
    "users.write")]
```

```text
Sistema propietario: ScopeOwners["developer-system"]
customKey:           dev-account.{accountId}
Permiso:             users.write
```

El propietario proviene de la configuración; nunca de route, query o body.

## 3. Configuración

```json
{
  "Security": {
    "Auth": {
      "PublicKeyPath": "Auth/public_key.pem",
      "SystemId": "<consumer-system-id>",
      "ValidIssuer": "https://auth.blikon.com",
      "ValidAudience": "<consumer-system-id>",
      "EnableSuperAdminBypass": false,
      "ScopeOwners": {
        "developer-system": "<developer-system-id>"
      }
    }
  }
}
```

| Propiedad | Uso |
| --- | --- |
| `PublicKeyPath` | Llave pública para validar la firma RSA |
| `SystemId` | Identificador de la API consumidora |
| `ValidIssuer` | Emisor aceptado |
| `ValidAudience` | Audience base requerida |
| `EnableSuperAdminBypass` | Omite permisos, pero no autenticación ni audiences |
| `ScopeOwners` | Allowlist (lista cerrada) de sistemas externos consultables |

Todos los valores deben pertenecer al mismo ambiente. No debe mezclarse
configuración de Development, Testing y Production.

## 4. Flujo completo

```text
1. Permissions define scopes, permisos y roles.
2. Security asigna un rol a un principal sobre una customKey.
3. Security resuelve el rol a permisos efectivos.
4. Security emite un JWT actualizado.
5. El cliente envía Authorization: Bearer <JWT>.
6. Security.Auth valida firma, issuer, audiences y vigencia.
7. SecureAuth resuelve la customKey solicitada.
8. SecureAuth busca el permiso efectivo dentro de scp.
9. La API ejecuta o rechaza el endpoint.
```

Después de asignar, modificar o revocar un rol, el cliente debe renovar su JWT.
Un token anterior puede conservar permisos desactualizados hasta expirar.

## 5. Estructura relevante del JWT

```json
{
  "iss": "https://auth.blikon.com",
  "aud": ["<consumer-system-id>", "<developer-system-id>"],
  "blikon_id": "<user-id>",
  "scp": {
    "<consumer-system-id>": {
      "system": ["spaces.read", "user.write"]
    },
    "<developer-system-id>": {
      "dev-account.123": ["users.read", "users.write"]
    }
  }
}
```

La DLL no busca nombres de roles; autoriza con los permisos efectivos de `scp`.

## 6. `customKey`, OR y AND

Una `customKey` puede ser estática (`system`) o dinámica
(`dev-account.{accountId}`). Los placeholders (valores reemplazables) se buscan:

```text
Route -> Query -> propiedad raíz del body JSON
```

Se aceptan strings, números y GUID; no se recorren objetos anidados.

Permisos separados por coma usan OR; basta con uno:

```csharp
[SecureAuth(
    "developer-system",
    "dev-account.{accountId}",
    "users.write,account.changename")]
```

Atributos apilados usan AND; todos deben cumplirse:

```csharp
[SecureAuth("system", "systems.read")]
[SecureAuth(
    "developer-system",
    "dev-account.{accountId}",
    "users.write")]
```

La comparación no distingue mayúsculas, pero exige identificadores completos.
No existen wildcards (comodines que representan múltiples valores).

## 7. Respuestas

| Situación | Resultado |
| --- | --- |
| Token ausente | `401 Unauthorized` |
| Firma, issuer, vigencia o audience inválidos | `401 Unauthorized` |
| Alias externo no configurado | `403 Forbidden` |
| `customKey` o placeholder ausente | `403 Forbidden` |
| `scp` mal formado | `403 Forbidden` |
| Token válido sin permiso | `403 Forbidden` |
| Audience, `customKey` y permiso presentes | Acceso autorizado |

```text
401 = la identidad o el destino del token no son aceptables.
403 = la identidad es válida, pero no tiene la autorización solicitada.
```

## 8. Administración de roles

Una API puede autenticarse como sistema ante Security API para asignar o revocar
roles. Este flujo es distinto de la validación realizada por la DLL:

```text
Sistema consumidor + secret
          -> Security API emite token técnico
          -> la API asigna o revoca un rol
          -> el usuario renueva su JWT
```

El token técnico debe separarse de los JWT de usuario. El secret no debe llegar
al cliente ni almacenarse en el repositorio.

## 9. Convivencia con Legacy

Durante una migración pueden coexistir:

| Esquema | Responsabilidad |
| --- | --- |
| `LegacyBearer` | Valida el JWT anterior de la aplicación |
| `Bearer` | Valida el JWT emitido por Security |

```csharp
builder.Services.AddCustomTokenAuth(
    builder.Configuration,
    useAsDefault: false);
```

- `[Authorize]` conserva el esquema predeterminado de la API.
- `[SecureAuth(...)]` selecciona explícitamente `Bearer`.
- `[AllowAnonymous]` se usa solo para acceso público intencional.
- Un token Legacy no debe autorizar `SecureAuth`.
- Un token Security no debe cambiar el comportamiento Legacy.

## 10. Roles locales frente a roles de Security

Un rol almacenado en la base local no concede permisos de Security. Son
asignaciones diferentes:

```text
Rol local de negocio
```

```text
Principal + sistema propietario + customKey + rol de Permissions
```

Si una operación actualiza ambos modelos, debe sincronizarlos y aplicar una
compensación (acción que restaura el estado cuando una operación parcial falla).

## 11. Riesgos y controles

### `EnableSuperAdminBypass`

Puede ocultar errores porque autoriza sin que el permiso exista en `scp`. Debe
estar deshabilitado por defecto y no utilizarse para validar la matriz real.

### Secretos en configuración

Los secretos no deben confirmarse en Git. Deben vivir en variables de entorno o
un secret manager (servicio especializado para almacenar credenciales). Si un
secreto real fue publicado, debe rotarse.

### Mezcla de ambientes

IDs, aliases, llaves, issuer y URLs deben pertenecer al mismo ambiente. Una
mezcla puede producir `401`, `403` o consultar al sistema equivocado.

### Tokens desactualizados

Cambiar un rol no modifica un JWT emitido. Se necesita una política de
renovación, expiración y, cuando aplique, revocación de sesiones.

### Fallos parciales

Si un flujo modifica la base local y Security API, puede dejar estados
inconsistentes. Debe ser idempotente (repetirlo no cambia el resultado después
de la primera ejecución), registrar resultados y ejecutar compensaciones.

### `customKey` incorrecta

Un permiso correcto sobre otra `customKey` no concede acceso. Deben existir
convenciones únicas como `system`, `space.{id}` y `dev-account.{id}`.

### Validación mínima

Cada endpoint debe probar:

- Sin token: `401`.
- Token inválido o vencido: `401`.
- Token válido sin permiso: `403`.
- Permiso correcto sobre otra `customKey`: `403`.
- Permiso y `customKey` correctos: acceso autorizado.
- Asignación, renovación, revocación y nueva renovación del JWT.

## 12. Middleware

```csharp
app.UseSecurityErrorReporting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
```

`UseAuthentication()` debe ejecutarse antes de `UseAuthorization()`.
