using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Security.Auth;

public class TokenAuthorizationHandler : AuthorizationHandler<CustomAuthorizeAttribute>
{
    private const string DefaultSpaceIdParameterName = "spaceId";

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly SecurityAuthOptions _authOptions;
    private readonly PublicKeyProvider _publicKeyProvider;
    private readonly ILogger<TokenAuthorizationHandler> _logger;

    public TokenAuthorizationHandler(
        IHttpContextAccessor httpContextAccessor,
        IOptions<SecurityAuthOptions> authOptions,
        PublicKeyProvider publicKeyProvider,
        ILogger<TokenAuthorizationHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _authOptions = authOptions.Value;
        _publicKeyProvider = publicKeyProvider;
        _logger = logger;

        if (string.IsNullOrWhiteSpace(_authOptions.SystemId))
            throw new InvalidOperationException("Security:Auth:SystemId no esta configurado.");

        if (string.IsNullOrWhiteSpace(_authOptions.ValidIssuer))
            throw new InvalidOperationException("Security:Auth:ValidIssuer no esta configurado.");

        if (string.IsNullOrWhiteSpace(_authOptions.ValidAudience))
            throw new InvalidOperationException("Security:Auth:ValidAudience no esta configurado.");
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CustomAuthorizeAttribute requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            context.Fail(new AuthorizationFailureReason(this, "No se encontro contexto HTTP."));
            return;
        }

        if (!httpContext.Request.Headers.TryGetValue("Authorization", out var authHeaderValues))
        {
            _logger.LogWarning("Authorization header no presente.");
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", "Token no proporcionado.");
            context.Fail(new AuthorizationFailureReason(this, "Token no proporcionado."));
            return;
        }

        var authHeader = authHeaderValues.ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Authorization header con esquema invalido: {HeaderValue}", authHeader);
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", "Esquema de autorizacion invalido.");
            context.Fail(new AuthorizationFailureReason(this, "Esquema de autorizacion invalido."));
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
                _logger.LogWarning("JwtValidator devolvio null.");
                await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", "No fue posible validar el token.");
                context.Fail(new AuthorizationFailureReason(this, "No fue posible validar el token."));
                return;
            }

            if (!jwtResult.IsValid)
            {
                var message = jwtResult.ErrorMessage ?? "Token invalido.";
                _logger.LogWarning("Token invalido: {Message}", message);
                await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", message);
                context.Fail(new AuthorizationFailureReason(this, message));
                return;
            }

            if (_authOptions.EnableSuperAdminBypass && IsSuperAdmin(jwtResult.Claims))
            {
                context.Succeed(requirement);
                return;
            }

            var scopes = ParseScopes(jwtResult);
            var authorizationResult = await AuthorizeRequirementAsync(httpContext, requirement, scopes);

            if (authorizationResult.IsAuthorized)
            {
                context.Succeed(requirement);
                return;
            }

            _logger.LogWarning("Permiso denegado. {Reason}", authorizationResult.Message);
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status403Forbidden, "forbidden", authorizationResult.Message);
            context.Fail(new AuthorizationFailureReason(this, authorizationResult.Message));
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "El claim scp tiene formato invalido para SystemId {SystemId}", _authOptions.SystemId);
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status403Forbidden, "forbidden", "El claim scp no tiene un formato valido.");
            context.Fail(new AuthorizationFailureReason(this, "El claim scp no tiene un formato valido."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error interno durante la validacion/autorizacion del token.");
            await WriteErrorResponseAsync(httpContext, StatusCodes.Status401Unauthorized, "unauthorized", "Error interno durante la validacion del token.");
            context.Fail(new AuthorizationFailureReason(this, "Error interno durante la validacion del token."));
        }
    }

    private async Task<AuthorizationCheckResult> AuthorizeRequirementAsync(
        HttpContext httpContext,
        CustomAuthorizeAttribute requirement,
        Dictionary<string, Dictionary<string, List<string>>> scopes)
    {
        return requirement switch
        {
            SystemAuthorizeAttribute systemRequirement => AuthorizeSystem(systemRequirement.Permission, scopes),
            PlaceAuthorizeAttribute placeRequirement => await AuthorizePlaceAsync(httpContext, placeRequirement.Permission, placeRequirement.SpaceIdParameterName, scopes),
            SystemOrPlaceAuthorizeAttribute hybridRequirement => await AuthorizeSystemOrPlaceAsync(httpContext, hybridRequirement, scopes),
            _ => AuthorizeSystem(requirement.Permission, scopes)
        };
    }

    private async Task<AuthorizationCheckResult> AuthorizeSystemOrPlaceAsync(
        HttpContext httpContext,
        SystemOrPlaceAuthorizeAttribute requirement,
        Dictionary<string, Dictionary<string, List<string>>> scopes)
    {
        var systemResult = string.IsNullOrWhiteSpace(requirement.SystemPermission)
            ? AuthorizationCheckResult.Denied("Permiso de sistema no configurado.")
            : AuthorizeSystem(requirement.SystemPermission, scopes);

        if (systemResult.IsAuthorized)
            return systemResult;

        var placeResult = string.IsNullOrWhiteSpace(requirement.PlacePermission)
            ? AuthorizationCheckResult.Denied("Permiso de place no configurado.")
            : await AuthorizePlaceAsync(httpContext, requirement.PlacePermission, requirement.SpaceIdParameterName, scopes);

        if (placeResult.IsAuthorized)
            return placeResult;

        return AuthorizationCheckResult.Denied(
            $"No tiene el permiso de sistema '{requirement.SystemPermission}' ni el permiso de place '{requirement.PlacePermission}'.");
    }

    private AuthorizationCheckResult AuthorizeSystem(
        string? permission,
        Dictionary<string, Dictionary<string, List<string>>> scopes)
    {
        if (string.IsNullOrWhiteSpace(permission))
            return AuthorizationCheckResult.Allowed();

        var requiredPermissions = SplitPermissions(permission);
        var permissions = GetPermissions(scopes, "system");

        return HasAnyRequiredPermission(permissions, requiredPermissions)
            ? AuthorizationCheckResult.Allowed()
            : AuthorizationCheckResult.Denied($"No tiene ninguno de los permisos de sistema requeridos: {permission}.");
    }

    private async Task<AuthorizationCheckResult> AuthorizePlaceAsync(
        HttpContext httpContext,
        string? permission,
        string? spaceIdParameterName,
        Dictionary<string, Dictionary<string, List<string>>> scopes)
    {
        if (string.IsNullOrWhiteSpace(permission))
            return AuthorizationCheckResult.Allowed();

        var resolvedSpaceId = await ResolveSpaceIdAsync(httpContext, spaceIdParameterName);
        if (string.IsNullOrWhiteSpace(resolvedSpaceId))
            return AuthorizationCheckResult.Denied($"{spaceIdParameterName ?? DefaultSpaceIdParameterName} requerido o invalido.");

        var placeKey = $"place.{resolvedSpaceId}";
        var requiredPermissions = SplitPermissions(permission);
        var permissions = GetPermissions(scopes, placeKey);

        return HasAnyRequiredPermission(permissions, requiredPermissions)
            ? AuthorizationCheckResult.Allowed()
            : AuthorizationCheckResult.Denied($"No tiene ninguno de los permisos requeridos para {placeKey}: {permission}.");
    }

    private Dictionary<string, Dictionary<string, List<string>>> ParseScopes(JwtValidator.JwtValidationResult jwtResult)
    {
        var scopes = new Dictionary<string, Dictionary<string, List<string>>>(StringComparer.OrdinalIgnoreCase);
        if (!jwtResult.Claims.TryGetValue("scp", out var scpJson) || string.IsNullOrWhiteSpace(scpJson))
            return scopes;

        using var doc = JsonDocument.Parse(scpJson);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            return scopes;

        foreach (var audienceProperty in doc.RootElement.EnumerateObject())
        {
            if (audienceProperty.Value.ValueKind != JsonValueKind.Object)
                continue;

            var scopeGroups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var groupProperty in audienceProperty.Value.EnumerateObject())
            {
                if (groupProperty.Value.ValueKind != JsonValueKind.Array)
                    continue;

                var permissions = new List<string>();
                foreach (var permissionElement in groupProperty.Value.EnumerateArray())
                {
                    var permission = permissionElement.GetString();
                    if (!string.IsNullOrWhiteSpace(permission))
                        permissions.Add(permission);
                }

                scopeGroups[groupProperty.Name] = permissions;
            }

            scopes[audienceProperty.Name] = scopeGroups;
        }

        return scopes;
    }

    private List<string> GetPermissions(
        Dictionary<string, Dictionary<string, List<string>>> scopes,
        string scopeGroupName)
    {
        if (!scopes.TryGetValue(_authOptions.SystemId, out var systemScopes))
            return new List<string>();

        return systemScopes.TryGetValue(scopeGroupName, out var permissions)
            ? permissions
            : new List<string>();
    }

    private static bool HasAnyRequiredPermission(IEnumerable<string> grantedPermissions, IEnumerable<string> requiredPermissions)
    {
        return requiredPermissions.Any(requiredPermission =>
            grantedPermissions.Contains(requiredPermission, StringComparer.OrdinalIgnoreCase));
    }

    private static string[] SplitPermissions(string permission)
    {
        return permission.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static bool IsSuperAdmin(IReadOnlyDictionary<string, string> claims)
    {
        return claims.TryGetValue("is_superadmin", out var value) &&
            bool.TryParse(value, out var isSuperAdmin) &&
            isSuperAdmin;
    }

    private static async Task<string?> ResolveSpaceIdAsync(HttpContext httpContext, string? parameterName)
    {
        var name = string.IsNullOrWhiteSpace(parameterName) ? DefaultSpaceIdParameterName : parameterName;

        if (httpContext.Request.RouteValues.TryGetValue(name, out var routeValue) &&
            TryNormalizeSpaceId(routeValue?.ToString(), out var routeSpaceId))
        {
            return routeSpaceId;
        }

        if (httpContext.Request.Query.TryGetValue(name, out var queryValue) &&
            TryNormalizeSpaceId(queryValue.FirstOrDefault(), out var querySpaceId))
        {
            return querySpaceId;
        }

        return await TryResolveSpaceIdFromJsonBodyAsync(httpContext, name);
    }

    private static async Task<string?> TryResolveSpaceIdFromJsonBodyAsync(HttpContext httpContext, string parameterName)
    {
        var request = httpContext.Request;
        if (request.ContentLength is null or 0 ||
            string.IsNullOrWhiteSpace(request.ContentType) ||
            !request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        request.EnableBuffering();
        request.Body.Position = 0;

        try
        {
            using var doc = await JsonDocument.ParseAsync(request.Body);
            if (TryFindJsonProperty(doc.RootElement, parameterName, out var value) &&
                TryNormalizeSpaceId(value, out var spaceId))
            {
                return spaceId;
            }
        }
        catch (JsonException)
        {
            return null;
        }
        finally
        {
            request.Body.Position = 0;
        }

        return null;
    }

    private static bool TryFindJsonProperty(JsonElement element, string propertyName, out string? value)
    {
        value = null;
        if (element.ValueKind != JsonValueKind.Object)
            return false;

        foreach (var property in element.EnumerateObject())
        {
            if (property.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value.ValueKind switch
                {
                    JsonValueKind.Number => property.Value.GetRawText(),
                    JsonValueKind.String => property.Value.GetString(),
                    _ => null
                };
                return value is not null;
            }
        }

        return false;
    }

    private static bool TryNormalizeSpaceId(string? rawValue, out string spaceId)
    {
        spaceId = string.Empty;
        if (string.IsNullOrWhiteSpace(rawValue))
            return false;

        rawValue = rawValue.Trim();
        if (!long.TryParse(rawValue, out var numericSpaceId) || numericSpaceId <= 0)
            return false;

        spaceId = numericSpaceId.ToString();
        return true;
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

    private sealed record AuthorizationCheckResult(bool IsAuthorized, string Message)
    {
        public static AuthorizationCheckResult Allowed() => new(true, string.Empty);
        public static AuthorizationCheckResult Denied(string message) => new(false, message);
    }
}

