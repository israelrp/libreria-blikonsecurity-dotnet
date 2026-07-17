# Security.Auth

Librería interna para APIs ASP.NET Core con:

- validación de JWT Bearer mediante firma RSA, issuer, audience y vigencia;
- autorización genérica mediante `SecureAuth`;
- reporte manual y automático de errores hacia Security API.

## Dependencias

La librería apunta a .NET 10. El proyecto consumidor debe poder resolver:

```xml
<FrameworkReference Include="Microsoft.AspNetCore.App" />
<PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="8.19.0" />
```

Una Web API creada con `Microsoft.NET.Sdk.Web` normalmente ya incluye el framework de ASP.NET Core.

## Configuración

`SystemId` identifica la API que consume la DLL. `ScopeOwners` es la allowlist (lista cerrada) de otros sistemas cuyos permisos puede consultar esa API.

```json
{
  "Security": {
    "Auth": {
      "PublicKeyPath": "Auth/public_key.pem",
      "SystemId": "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d",
      "ValidIssuer": "https://auth.blikon.com",
      "ValidAudience": "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d",
      "EnableSuperAdminBypass": true,
      "ScopeOwners": {
        "developer-system": "57eb7549-aad1-4063-8996-7487e250f87d"
      }
    },
    "Errors": {
      "BaseUrl": "https://security-api.example.com/api/v1",
      "Secret": "secret-del-sistema"
    }
  }
}
```

Reglas de configuración:

- Los aliases de `ScopeOwners` usan kebab-case (palabras minúsculas separadas por guiones).
- Cada valor de `ScopeOwners` debe ser un GUID diferente de `SystemId`.
- `EnableSuperAdminBypass` permite omitir el permiso cuando `is_superadmin` es `true`, pero nunca omite la firma, issuer, vigencia ni audiences requeridos.

## Registro

```csharp
using Security.Auth;

builder.Services.AddCustomTokenAuth(builder.Configuration);
builder.Services.AddSecurityErrorReporting(builder.Configuration);

var app = builder.Build();

app.UseSecurityErrorReporting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
```

## Autorización con `SecureAuth`

La regla fundamental es:

```text
aud determina qué sistemas pueden considerarse.
scp determina qué permisos existen dentro de cada sistema.
```

Este token se usará en los ejemplos:

```json
{
  "iss": "https://auth.blikon.com",
  "aud": [
    "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d",
    "57eb7549-aad1-4063-8996-7487e250f87d"
  ],
  "scp": {
    "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d": {
      "system": ["systems.update"],
      "place.415": ["user2place.read"]
    },
    "57eb7549-aad1-4063-8996-7487e250f87d": {
      "dev-account.2": ["develop.write", "account.changename"]
    }
  }
}
```

La audiencia requerida depende del propietario del scope solicitado:

- con el constructor corto, el token debe incluir al sistema consumidor en `aud`;
- con el constructor largo, el token debe incluir en `aud` al sistema configurado en `ScopeOwners`. El sistema consumidor no es obligatorio, lo que permite endpoints puente que autorizan exclusivamente con scopes externos.

### Scope del sistema consumidor

Usa el constructor corto para consultar `scp[SystemId]`:

```csharp
[SecureAuth("system", "systems.update")]
[HttpPut("systems/{id}")]
public IActionResult UpdateSystem(string id) => Ok();
```

La validación busca:

```text
scp[SystemId]["system"] contiene "systems.update"
```

`place` no recibe tratamiento especial; es otro customKey:

```csharp
[SecureAuth("place.{spaceId}", "user2place.read")]
[HttpGet("places/{spaceId}/users")]
public IActionResult GetUsers(string spaceId) => Ok();
```

Para `spaceId = 415`, se consulta `scp[SystemId]["place.415"]`.

### Scope de otro sistema

Usa el constructor largo con un alias registrado en `ScopeOwners`:

```csharp
[SecureAuth(
    "developer-system",
    "dev-account.{accountId}",
    "develop.write")]
[HttpPut("developer-accounts/{accountId}")]
public IActionResult UpdateDeveloperAccount(string accountId) => Ok();
```

Para `accountId = 2`, se consulta:

```text
scp[ScopeOwners["developer-system"]]["dev-account.2"]
```

El propietario del scope se declara en el atributo; nunca se recibe desde route, query o body.

### Placeholder desde `[FromBody]`

También puede resolverse una propiedad raíz del JSON:

```csharp
public sealed class UpdateDeveloperAccountRequest
{
    public string AccountId { get; set; } = string.Empty;
}

[SecureAuth(
    "developer-system",
    "dev-account.{accountId}",
    "develop.write")]
[HttpPost("developer-accounts")]
public IActionResult UpdateDeveloperAccount(
    [FromBody] UpdateDeveloperAccountRequest request) => Ok();
```

Body:

```json
{
  "accountId": "2"
}
```

Los placeholders se buscan en este orden:

```text
Route → Query → propiedad raíz del body JSON
```

Se aceptan strings, números y GUID. No se recorren objetos anidados.

### OR y AND

Varios permisos separados por comas usan OR: basta con tener uno.

```csharp
[SecureAuth(
    "developer-system",
    "dev-account.{accountId}",
    "develop.write,account.changename")]
```

Varios atributos apilados usan AND: deben cumplirse todos.

```csharp
[SecureAuth("system", "systems.read")]
[SecureAuth(
    "developer-system",
    "dev-account.{accountId}",
    "develop.write")]
```

Las claves de scope y los permisos son exactos y case-insensitive (no distinguen mayúsculas y minúsculas). No existen wildcards (comodines como `users.*`) ni coincidencias parciales.

### Respuestas de autorización

| Resultado | Estado |
| --- | --- |
| Token ausente, firma/issuer/vigencia inválidos, `ValidAudience` o `SystemId` consumidor ausentes de `aud` | `401 Unauthorized` |
| Alias externo desconocido o propietario externo ausente de `aud` | `403 Forbidden` |
| Scope, placeholder o permiso ausente; `scp` mal formado | `403 Forbidden` |
| Audience, scope y al menos un permiso requeridos presentes | Acceso autorizado |

## Reporte de errores

`UseSecurityErrorReporting()` captura excepciones no controladas, las registra en Security API y responde `500 application/json`.

Para reportar manualmente una excepción:

```csharp
catch (Exception ex)
{
    await _errorReporter.ReportAsync(
        ex,
        HttpContext,
        statusCode: StatusCodes.Status400BadRequest,
        criticality: "low");

    return BadRequest(new { message = "La solicitud no es válida." });
}
```

La librería completa automáticamente datos como tipo de excepción, mensaje, traceback (ruta de llamadas que originó el error), archivo, función, línea, endpoint, método, `requestId` y criticidad.
