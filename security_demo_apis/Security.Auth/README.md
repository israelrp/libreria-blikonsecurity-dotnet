# Security.Auth

Libreria interna para APIs .NET con:

- Validacion Bearer JWT con firma RSA, issuer, audience y lifetime.
- Autorizacion por permisos de sistema y permisos por place.
- Reporte de errores hacia Security API.
- Middleware opcional para capturar excepciones no manejadas.

## Configuracion

```json
{
  "Security": {
    "Auth": {
      "PublicKeyPath": "Auth/public_key.pem",
      "SystemId": "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d",
      "ValidIssuer": "https://auth.blikon.com",
      "ValidAudience": "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d",
      "EnableSuperAdminBypass": true
    },
    "Errors": {
      "BaseUrl": "https://security-api.dev.com.pro/api/v1",
      "Secret": "secret-del-sistema"
    }
  }
}
```

`Security:Auth:SystemId` identifica el sistema/API que recibe el token. La libreria busca permisos dentro de `scp[SystemId]`.

`Security:Auth:ValidAudience` debe coincidir con el audience esperado del JWT entrante.

`Security:Auth:EnableSuperAdminBypass` permite que un token valido con `is_superadmin: true` pase la autorizacion sin exigir el permiso exacto. La validacion de firma, issuer, audience y expiracion nunca se omite.

`Security:Errors:Secret` es el secreto saliente que usa este sistema para autenticarse al registrar errores.

## Dependencias requeridas

Al importar esta libreria en otro proyecto, confirma que el proyecto consumidor pueda resolver estas dependencias:

```xml
<FrameworkReference Include="Microsoft.AspNetCore.App" />
<PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="8.19.0" />
```

Si el proyecto destino ya es una Web API con `Microsoft.NET.Sdk.Web`, normalmente el framework de ASP.NET Core ya esta disponible. Si es una libreria o proyecto con `Microsoft.NET.Sdk`, agrega el `FrameworkReference` para evitar errores de compilacion.

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

## Autorizacion

### Permisos de sistema

Usa `SystemAuthorize` para tokens system-to-system. La libreria valida el permiso exacto dentro de `scp[SystemId].system[]`.

```csharp
[SystemAuthorize("clientauth.send")]
[HttpPost("send-code")]
public IActionResult SendCode() => Ok();
```

Token esperado:

```json
{
  "typ": "system",
  "aud": ["fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d"],
  "scp": {
    "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d": {
      "system": ["clientauth.send"]
    }
  }
}
```

### Permisos por place

Usa `PlaceAuthorize` para tokens de usuario con permisos por place. La libreria valida el permiso exacto dentro de `scp[SystemId].place.{spaceId}[]`.

```csharp
[PlaceAuthorize("collections.read")]
[HttpGet("collections/{spaceId}")]
public IActionResult GetCollections(int spaceId) => Ok();
```

Token esperado:

```json
{
  "typ": "user",
  "aud": ["fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d"],
  "scp": {
    "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d": {
      "place.269": ["collections.read"]
    }
  }
}
```

`PlaceAuthorize` busca el `spaceId` en este orden:

- route values: `/api/collections/{spaceId}`
- query string: `?spaceId=269`
- body JSON: `{ "spaceId": 269 }`

Si el parametro se llama distinto, configuralo en el atributo:

```csharp
[PlaceAuthorize("collections.read", SpaceIdParameterName = "placeId")]
[HttpGet("places/{placeId}/collections")]
public IActionResult GetCollections(int placeId) => Ok();
```

### Aceptar sistema o place

Usa `SystemOrPlaceAuthorize` cuando el endpoint deba aceptar un sistema con permiso de sistema o un usuario con permiso por place.

```csharp
[SystemOrPlaceAuthorize(
    SystemPermission = "clientauth.send",
    PlacePermission = "collections.read")]
[HttpGet("collections/{spaceId}")]
public IActionResult GetCollections(int spaceId) => Ok();
```

Este atributo autoriza con semantica OR:

- pasa si existe `clientauth.send` en `scp[SystemId].system[]`;
- o pasa si existe `collections.read` en `scp[SystemId].place.{spaceId}[]`.

Si apilas `[SystemAuthorize]` y `[PlaceAuthorize]` en un mismo endpoint, ASP.NET Authorization los tratara como AND: el token debe cumplir ambos requisitos.

### Compatibilidad temporal

`CustomAuthorize("permiso")` sigue disponible y se interpreta como autorizacion de sistema contra `scp[SystemId].system[]`. Para codigo nuevo usa `SystemAuthorize`, `PlaceAuthorize` o `SystemOrPlaceAuthorize`.

### Reglas importantes

- Los permisos son exactos y case-insensitive.
- No hay wildcard por ahora.
- No se compara por sufijo: `users.read` no cubre `collections.read`.
- Token invalido, expirado, con firma invalida, issuer invalido o audience invalido => `401`.
- Token valido sin permiso suficiente => `403`.

## Reporte manual de errores

Para reportar una excepcion capturada y conservar una respuesta personalizada al cliente, usa el overload simplificado:

```csharp
catch (Exception ex)
{
    await _errorReporter.ReportAsync(ex, HttpContext);
    return StatusCode(500, new { message = "No fue posible procesar la solicitud." });
}
```

La libreria detecta automaticamente `ExceptionType`, `ErrorMessage`, `Traceback`, archivo, funcion, linea, endpoint, metodo, `requestId` y criticidad. La criticidad usa la misma clasificacion del middleware automatico.

Puedes sobrescribir valores opcionales cuando el caso lo requiera:

```csharp
catch (Exception ex)
{
    await _errorReporter.ReportAsync(
        ex,
        HttpContext,
        statusCode: StatusCodes.Status400BadRequest,
        criticality: "low",
        additionalInfo: new Dictionary<string, object?>
        {
            ["actorType"] = "user",
            ["userId"] = userId
        });

    return BadRequest(new { message = "La solicitud no es valida." });
}
```

Si necesitas control total del payload, tambien puedes enviar el modelo completo:

```csharp
public sealed class MyService
{
    private readonly ISecurityErrorReporter _errorReporter;

    public MyService(ISecurityErrorReporter errorReporter)
    {
        _errorReporter = errorReporter;
    }

    public async Task ReportAsync()
    {
        await _errorReporter.ReportAsync(new SecurityErrorReport
        {
            ExceptionType = "ValueError",
            ErrorMessage = "Invalid access token provided",
            Criticality = "critical",
            Traceback = "Traceback ...",
            FileName = "authentication_service.py",
            FunctionName = "validate_access_token",
            LineNumber = 128,
            Endpoint = "/api/v1/authentication/tokens/refresh",
            Method = "POST",
            StatusCode = 500,
            AdditionalInfo = new Dictionary<string, object?>
            {
                ["actorType"] = "system",
                ["requestId"] = "req_123456"
            }
        });
    }
}
```

## Middleware de errores

`UseSecurityErrorReporting()` captura excepciones no manejadas, obtiene un token con `POST /auth/systems`, registra el error con `POST /errors` y responde `500 application/json`.

El middleware autocompleta datos como `exceptionType`, `errorMessage`, `traceback`, `endpoint`, `method`, `statusCode`, `requestId`, `path`, `queryString` y `host`.
