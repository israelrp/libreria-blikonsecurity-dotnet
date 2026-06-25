# Security.Auth

Libreria interna para APIs .NET con:

- Validacion/autorizacion Bearer JWT por permisos.
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
      "ValidAudience": "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d"
    },
    "Errors": {
      "BaseUrl": "https://security-api.dev.com.pro/api/v1",
      "Secret": "secret-del-sistema"
    }
  }
}
```

`Security:Auth:SystemId` se usa tanto para validar permisos del JWT entrante como para autenticar el sistema al registrar errores. `Security:Errors:Secret` es el secreto saliente del sistema.

## Dependencias requeridas

Al importar esta libreria en otro proyecto, confirma que el proyecto consumidor pueda resolver estas dependencias si no instalar desde nugget managger:

  <FrameworkReference Include="Microsoft.AspNetCore.App" />

  <PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="8.19.0" />


`Microsoft.AspNetCore.App` es necesario por los tipos de autenticacion/autorizacion y middleware de ASP.NET Core que usa la libreria (`Microsoft.AspNetCore.Authentication`, `Microsoft.AspNetCore.Authorization`, `Microsoft.AspNetCore.Http`, `Microsoft.Extensions.*`). `Microsoft.IdentityModel.JsonWebTokens` aporta `JsonWebTokenHandler` y se apoya en `Microsoft.IdentityModel.Tokens` para validar firma, issuer, audience y lifetime del JWT.

Si el proyecto destino ya es una Web API con `Microsoft.NET.Sdk.Web`, normalmente el framework de ASP.NET Core ya esta disponible. Si es una libreria o proyecto con `Microsoft.NET.Sdk`, agrega el `FrameworkReference` para evitar errores de compilacion al resolver esos namespaces.

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

```csharp
[CustomAuthorize("catalogopaises.read")]
[HttpGet("countries")]
public IActionResult GetCountries() => Ok();
```

Para permitir el acceso con cualquiera de varios permisos, separalos por coma:

```csharp
[CustomAuthorize("catalogopaises.read,catalogopaises.update")]
[HttpGet("countries")]
public IActionResult GetCountries() => Ok();
```

La libreria valida firma RSA, issuer, audience, lifetime y permisos en el claim `scp` bajo el `SystemId` configurado. Cuando se configuran varios permisos en un mismo atributo, autoriza si el token contiene al menos uno de ellos.

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
