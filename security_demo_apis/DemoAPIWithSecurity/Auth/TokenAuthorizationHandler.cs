using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace DemoAPIWithSecurity.Auth;

public class TokenAuthorizationHandler : AuthorizationHandler<CustomAuthorizeAttribute>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuthOptions _authOptions;
    private readonly PublicKeyProvider _publicKeyProvider;

    public TokenAuthorizationHandler(
        IHttpContextAccessor httpContextAccessor,
        IOptions<AuthOptions> authOptions,
        PublicKeyProvider publicKeyProvider)
    {
        _httpContextAccessor = httpContextAccessor;
        _authOptions = authOptions.Value;
        _publicKeyProvider = publicKeyProvider;

        if (string.IsNullOrWhiteSpace(_authOptions.SystemId))
            throw new InvalidOperationException("AuthSettings:SystemId no está configurado.");

        if (string.IsNullOrWhiteSpace(_authOptions.ValidIssuer))
            throw new InvalidOperationException("AuthSettings:ValidIssuer no está configurado.");

        if (string.IsNullOrWhiteSpace(_authOptions.ValidAudience))
            throw new InvalidOperationException("AuthSettings:ValidAudience no está configurado.");
    }

    /// <summary>
    /// HandleRequirementAsync es el método que se ejecuta cada vez que una acción o controlador con [CustomAuthorize] es invocado.
    /// Aquí es donde hacemos toda la lógica de validación del token, extracción de permisos, y finalmente decidimos si el contexto cumple con el requisito de autorización o no.
    /// </summary>
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CustomAuthorizeAttribute requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            context.Fail(new AuthorizationFailureReason(this, "No se encontró contexto HTTP."));
            return;
        }

        if (!httpContext.Request.Headers.TryGetValue("Authorization", out var authHeaderValues))
        {
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", "Token no proporcionado.");
            context.Fail(new AuthorizationFailureReason(this, "Token no proporcionado."));
            return;
        }

        var authHeader = authHeaderValues.ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", "Esquema de autorización inválido.");
            context.Fail(new AuthorizationFailureReason(this, "Esquema de autorización inválido."));
            return;
        }

        var token = authHeader["Bearer ".Length..].Trim();

        try
        {
            var jwtResult = await JwtValidator.ValidarTokenAsync(
                token,
                _publicKeyProvider.PublicKeyPem,
                _authOptions.ValidIssuer,
                _authOptions.ValidAudience);

            if (jwtResult is null)
            {
                await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", "No fue posible validar el token.");
                context.Fail(new AuthorizationFailureReason(this, "No fue posible validar el token."));
                return;
            }

            if (!jwtResult.IsValid)
            {
                var message = jwtResult.ErrorMessage ?? "Token inválido.";
                await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", message);
                context.Fail(new AuthorizationFailureReason(this, message));
                return;
            }

            var permisosDelSistema = new List<string>();
            if (jwtResult.Claims.TryGetValue("scp", out string? scpJson) && !string.IsNullOrEmpty(scpJson))
            {
                try
                {
                    using var doc = JsonDocument.Parse(scpJson);
                    if (doc.RootElement.TryGetProperty(_authOptions.SystemId, out var systemGroup) &&
                        systemGroup.TryGetProperty("system", out var systemArray) &&
                        systemArray.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var element in systemArray.EnumerateArray())
                        {
                            var permiso = element.GetString();
                            if (!string.IsNullOrEmpty(permiso))
                            {
                                permisosDelSistema.Add(permiso);
                            }
                        }
                    }
                }
                catch
                {
                    await WriteErrorResponseAsync(httpContext, StatusCodes.Status403Forbidden, "forbidden", "El claim scp no tiene un formato válido.");
                    context.Fail(new AuthorizationFailureReason(this, "El claim scp no tiene un formato válido."));
                    return;
                }
            }

            if (string.IsNullOrEmpty(requirement.Permission) ||
                permisosDelSistema.Contains(requirement.Permission, StringComparer.OrdinalIgnoreCase))
            {
                context.Succeed(requirement);
                return;
            }

            var forbiddenMessage = $"No tiene el permiso requerido: {requirement.Permission}.";
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status403Forbidden, "forbidden", forbiddenMessage);
            context.Fail(new AuthorizationFailureReason(this, forbiddenMessage));
        }
        catch
        {
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", "Error interno durante la validación del token.");
            context.Fail(new AuthorizationFailureReason(this, "Error interno durante la validación del token."));
        }
    }

    private static async Task WriteErrorResponseAsync(HttpContext httpContext, int statusCode, string error, string message)
    {
        if (httpContext.Response.HasStarted)
            return;

        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.ContentType = "application/json";

        var payload = JsonSerializer.Serialize(new
        {
            error,
            message
        });

        await httpContext.Response.WriteAsync(payload);
    }
}
