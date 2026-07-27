using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Security.Auth;

public sealed class TokenAuthorizationHandler : AuthorizationHandler<SecureAuthAttribute>
{
    private static readonly Regex PlaceholderRegex = new(
        "\\{(?<name>[^{}]+)\\}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly SecurityAuthOptions _authOptions;
    private readonly ILogger<TokenAuthorizationHandler> _logger;
    private readonly bool _detailedAuthorizationLogsEnabled;

    public TokenAuthorizationHandler(
        IHttpContextAccessor httpContextAccessor,
        IOptions<SecurityAuthOptions> authOptions,
        PublicKeyProvider publicKeyProvider,
        ILogger<TokenAuthorizationHandler> logger,
        IHostEnvironment? hostEnvironment = null)
    {
        _httpContextAccessor = httpContextAccessor;
        _authOptions = authOptions.Value;
        _ = publicKeyProvider;
        _logger = logger;
        _detailedAuthorizationLogsEnabled =
            hostEnvironment?.IsDevelopment() == true || hostEnvironment?.IsStaging() == true;

        if (string.IsNullOrWhiteSpace(_authOptions.SystemId))
            throw new InvalidOperationException("Security:Auth:SystemId no esta configurado.");

        if (string.IsNullOrWhiteSpace(_authOptions.ValidIssuer))
            throw new InvalidOperationException("Security:Auth:ValidIssuer no esta configurado.");

        if (string.IsNullOrWhiteSpace(_authOptions.ValidAudience))
            throw new InvalidOperationException("Security:Auth:ValidAudience no esta configurado.");
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SecureAuthAttribute requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            context.Fail(new AuthorizationFailureReason(this, "No se encontro contexto HTTP."));
            return;
        }

        if (context.User.Identity?.IsAuthenticated != true)
        {
            await DenyAsync(
                context,
                httpContext,
                StatusCodes.Status401Unauthorized,
                "unauthorized",
                "Token no autenticado.");
            return;
        }

        try
        {
            LogAuthorizationEvaluation(httpContext, requirement);

            var scopeOwnerResult = ResolveScopeOwner(requirement.ScopeOwner);
            if (!scopeOwnerResult.IsValid)
            {
                LogAuthorizationDenied(httpContext, scopeOwnerResult.Message);
                await DenyAsync(context, httpContext, StatusCodes.Status403Forbidden, "forbidden", scopeOwnerResult.Message);
                return;
            }

            var requiredAudience = requirement.ScopeOwner is null
                ? _authOptions.ValidAudience
                : scopeOwnerResult.SystemId!;

            var jwtResult = JwtValidator.FromPrincipal(context.User);

            if (!ContainsAudience(jwtResult.Audiences, requiredAudience) ||
                requirement.ScopeOwner is null &&
                !ContainsAudience(jwtResult.Audiences, _authOptions.SystemId))
            {
                const string message = "El token no esta destinado al sistema requerido.";
                LogAuthorizationDenied(httpContext, message);
                await DenyAsync(context, httpContext, StatusCodes.Status401Unauthorized, "unauthorized", message);
                return;
            }

            if (_authOptions.EnableSuperAdminBypass && IsSuperAdmin(jwtResult.Claims))
            {
                LogAuthorizationSucceeded(httpContext, requirement, "superadmin_bypass");
                context.Succeed(requirement);
                return;
            }

            var scopeKeyResult = await ResolveScopeKeyAsync(httpContext, requirement.ScopeKey);
            if (!scopeKeyResult.IsValid)
            {
                LogAuthorizationDenied(httpContext, scopeKeyResult.Message);
                await DenyAsync(context, httpContext, StatusCodes.Status403Forbidden, "forbidden", scopeKeyResult.Message);
                return;
            }

            var requiredPermissions = SplitPermissions(requirement.Permission);
            if (requiredPermissions.Length == 0)
            {
                const string message = "No se configuro ningun permiso requerido.";
                LogAuthorizationDenied(httpContext, message);
                await DenyAsync(context, httpContext, StatusCodes.Status403Forbidden, "forbidden", message);
                return;
            }

            var scopes = ParseScopes(jwtResult);
            var grantedPermissions = GetPermissions(scopes, scopeOwnerResult.SystemId!, scopeKeyResult.ScopeKey!);
            if (HasAnyRequiredPermission(grantedPermissions, requiredPermissions))
            {
                LogAuthorizationSucceeded(httpContext, requirement, "required_permission_granted");
                context.Succeed(requirement);
                return;
            }

            var deniedMessage =
                $"No tiene ninguno de los permisos requeridos en '{scopeKeyResult.ScopeKey}': {requirement.Permission}.";
            LogPermissionDenied(
                httpContext,
                jwtResult,
                scopes,
                scopeOwnerResult.SystemId!,
                scopeKeyResult.ScopeKey!,
                requiredPermissions,
                grantedPermissions);
            await DenyAsync(context, httpContext, StatusCodes.Status403Forbidden, "forbidden", deniedMessage);
        }
        catch (JsonException ex)
        {
            LogAuthorizationDenied(httpContext, "El claim scp tiene formato invalido.", ex);
            await DenyAsync(
                context,
                httpContext,
                StatusCodes.Status403Forbidden,
                "forbidden",
                "El claim scp no tiene un formato valido.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error interno durante la validacion/autorizacion del token.");
            await DenyAsync(
                context,
                httpContext,
                StatusCodes.Status401Unauthorized,
                "unauthorized",
                "Error interno durante la validacion del token.");
        }
    }

    private ScopeOwnerResolution ResolveScopeOwner(string? scopeOwner)
    {
        if (scopeOwner is null)
            return ScopeOwnerResolution.Valid(_authOptions.SystemId);

        if (string.IsNullOrWhiteSpace(scopeOwner))
            return ScopeOwnerResolution.Invalid("El alias del propietario de scope esta vacio.");

        var configuredOwner = _authOptions.ScopeOwners.FirstOrDefault(entry =>
            entry.Key.Equals(scopeOwner, StringComparison.OrdinalIgnoreCase));

        return string.IsNullOrWhiteSpace(configuredOwner.Key)
            ? ScopeOwnerResolution.Invalid($"El propietario de scope '{scopeOwner}' no esta configurado.")
            : ScopeOwnerResolution.Valid(configuredOwner.Value);
    }

    private static bool ContainsAudience(IEnumerable<string> audiences, string requiredAudience)
    {
        return audiences.Contains(requiredAudience, StringComparer.OrdinalIgnoreCase);
    }

    private static async Task<ScopeKeyResolution> ResolveScopeKeyAsync(
        HttpContext httpContext,
        string scopeKeyTemplate)
    {
        if (string.IsNullOrWhiteSpace(scopeKeyTemplate))
            return ScopeKeyResolution.Invalid("ScopeKey no esta configurado.");

        var matches = PlaceholderRegex.Matches(scopeKeyTemplate);
        var templateWithoutPlaceholders = PlaceholderRegex.Replace(scopeKeyTemplate, string.Empty);
        if (templateWithoutPlaceholders.Contains('{') || templateWithoutPlaceholders.Contains('}'))
            return ScopeKeyResolution.Invalid($"ScopeKey '{scopeKeyTemplate}' contiene una plantilla invalida.");

        if (matches.Count == 0)
            return ScopeKeyResolution.Valid(scopeKeyTemplate);

        Dictionary<string, string>? bodyValues = null;
        var resolvedScopeKey = new StringBuilder(scopeKeyTemplate);

        foreach (var placeholderName in matches
                     .Select(match => match.Groups["name"].Value)
                     .Distinct(StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(placeholderName))
                return ScopeKeyResolution.Invalid($"ScopeKey '{scopeKeyTemplate}' contiene un placeholder vacio.");

            var value = TryGetRouteValue(httpContext, placeholderName)
                ?? TryGetQueryValue(httpContext, placeholderName);

            if (value is null)
            {
                bodyValues ??= await ReadRootBodyValuesAsync(httpContext);
                bodyValues.TryGetValue(placeholderName, out value);
            }

            if (string.IsNullOrWhiteSpace(value))
                return ScopeKeyResolution.Invalid($"No fue posible resolver '{placeholderName}' para ScopeKey.");

            resolvedScopeKey.Replace($"{{{placeholderName}}}", value);
        }

        return ScopeKeyResolution.Valid(resolvedScopeKey.ToString());
    }

    private static string? TryGetRouteValue(HttpContext httpContext, string name)
    {
        var routeValue = httpContext.Request.RouteValues.FirstOrDefault(entry =>
            entry.Key.Equals(name, StringComparison.OrdinalIgnoreCase));

        return NormalizeRequestValue(routeValue.Value?.ToString());
    }

    private static string? TryGetQueryValue(HttpContext httpContext, string name)
    {
        var queryValue = httpContext.Request.Query.FirstOrDefault(entry =>
            entry.Key.Equals(name, StringComparison.OrdinalIgnoreCase));

        return NormalizeRequestValue(queryValue.Value.FirstOrDefault());
    }

    private static async Task<Dictionary<string, string>> ReadRootBodyValuesAsync(HttpContext httpContext)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var request = httpContext.Request;

        if (request.ContentLength == 0 ||
            string.IsNullOrWhiteSpace(request.ContentType) ||
            !request.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return values;
        }

        request.EnableBuffering();
        request.Body.Position = 0;

        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return values;

            foreach (var property in document.RootElement.EnumerateObject())
            {
                var value = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.Number => property.Value.GetRawText(),
                    _ => null
                };

                value = NormalizeRequestValue(value);
                if (value is not null)
                    values[property.Name] = value;
            }
        }
        catch (JsonException)
        {
            return values;
        }
        finally
        {
            request.Body.Position = 0;
        }

        return values;
    }

    private static string? NormalizeRequestValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static Dictionary<string, Dictionary<string, List<string>>> ParseScopes(
        JwtValidator.JwtValidationResult jwtResult)
    {
        var scopes = new Dictionary<string, Dictionary<string, List<string>>>(StringComparer.OrdinalIgnoreCase);
        if (!jwtResult.Claims.TryGetValue("scp", out var scpJson) || string.IsNullOrWhiteSpace(scpJson))
            return scopes;

        using var document = JsonDocument.Parse(scpJson);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            return scopes;

        foreach (var ownerProperty in document.RootElement.EnumerateObject())
        {
            if (ownerProperty.Value.ValueKind != JsonValueKind.Object)
                continue;

            var scopeGroups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var groupProperty in ownerProperty.Value.EnumerateObject())
            {
                if (groupProperty.Value.ValueKind != JsonValueKind.Array)
                    continue;

                var permissions = groupProperty.Value
                    .EnumerateArray()
                    .Where(element => element.ValueKind == JsonValueKind.String)
                    .Select(element => element.GetString())
                    .Where(permission => !string.IsNullOrWhiteSpace(permission))
                    .Select(permission => permission!)
                    .ToList();

                scopeGroups[groupProperty.Name] = permissions;
            }

            scopes[ownerProperty.Name] = scopeGroups;
        }

        return scopes;
    }

    private static IReadOnlyCollection<string> GetPermissions(
        Dictionary<string, Dictionary<string, List<string>>> scopes,
        string scopeOwnerId,
        string scopeKey)
    {
        if (!scopes.TryGetValue(scopeOwnerId, out var ownerScopes))
            return Array.Empty<string>();

        return ownerScopes.TryGetValue(scopeKey, out var permissions)
            ? permissions
            : Array.Empty<string>();
    }

    private static bool HasAnyRequiredPermission(
        IEnumerable<string> grantedPermissions,
        IEnumerable<string> requiredPermissions)
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

    private void LogAuthorizationEvaluation(HttpContext httpContext, SecureAuthAttribute requirement)
    {
        if (!_detailedAuthorizationLogsEnabled)
            return;

        _logger.LogDebug(
            "Evaluando autorizacion. TraceId: {TraceId}, Method: {Method}, Path: {Path}, " +
            "ScopeOwnerAlias: {ScopeOwnerAlias}, ScopeKeyTemplate: {ScopeKeyTemplate}, " +
            "RequiredPermissions: {RequiredPermissions}, ConsumerSystemId: {ConsumerSystemId}.",
            httpContext.TraceIdentifier,
            httpContext.Request.Method,
            httpContext.Request.Path,
            requirement.ScopeOwner ?? "(consumer-system)",
            requirement.ScopeKey,
            requirement.Permission,
            _authOptions.SystemId);
    }

    private void LogAuthorizationSucceeded(
        HttpContext httpContext,
        SecureAuthAttribute requirement,
        string reason)
    {
        if (!_detailedAuthorizationLogsEnabled)
            return;

        _logger.LogDebug(
            "Autorizacion concedida. TraceId: {TraceId}, Path: {Path}, ScopeKey: {ScopeKey}, " +
            "RequiredPermissions: {RequiredPermissions}, Reason: {Reason}.",
            httpContext.TraceIdentifier,
            httpContext.Request.Path,
            requirement.ScopeKey,
            requirement.Permission,
            reason);
    }

    private void LogAuthorizationDenied(HttpContext httpContext, string reason, Exception? exception = null)
    {
        if (_detailedAuthorizationLogsEnabled)
        {
            _logger.LogWarning(
                exception,
                "Autorizacion rechazada. TraceId: {TraceId}, Method: {Method}, Path: {Path}, Reason: {Reason}.",
                httpContext.TraceIdentifier,
                httpContext.Request.Method,
                httpContext.Request.Path,
                reason);
            return;
        }

        _logger.LogWarning(
            "Autorizacion rechazada. TraceId: {TraceId}.",
            httpContext.TraceIdentifier);
    }

    private void LogPermissionDenied(
        HttpContext httpContext,
        JwtValidator.JwtValidationResult jwtResult,
        Dictionary<string, Dictionary<string, List<string>>> scopes,
        string scopeOwnerId,
        string scopeKey,
        IReadOnlyCollection<string> requiredPermissions,
        IReadOnlyCollection<string> grantedPermissions)
    {
        if (!_detailedAuthorizationLogsEnabled)
        {
            LogAuthorizationDenied(httpContext, "Permiso requerido no concedido.");
            return;
        }

        var hasScopeClaim = jwtResult.Claims.TryGetValue("scp", out var scpClaim) &&
            !string.IsNullOrWhiteSpace(scpClaim);
        var hasScopeOwner = scopes.TryGetValue(scopeOwnerId, out var ownerScopes);
        var hasScopeKey = hasScopeOwner && ownerScopes!.ContainsKey(scopeKey);
        var reason = !hasScopeClaim
            ? "El token no contiene un claim scp utilizable."
            : !hasScopeOwner
                ? "El claim scp no contiene el ScopeOwner requerido."
                : !hasScopeKey
                    ? "El ScopeOwner existe, pero no contiene el ScopeKey requerido."
                    : "El ScopeKey existe, pero no contiene ninguno de los permisos requeridos.";

        _logger.LogWarning(
            "Autorizacion rechazada. TraceId: {TraceId}, Method: {Method}, Path: {Path}, " +
            "Reason: {Reason}, ScopeOwnerId: {ScopeOwnerId}, ScopeKey: {ScopeKey}, " +
            "RequiredPermissions: {RequiredPermissions}, GrantedPermissions: {GrantedPermissions}.",
            httpContext.TraceIdentifier,
            httpContext.Request.Method,
            httpContext.Request.Path,
            reason,
            scopeOwnerId,
            scopeKey,
            string.Join(",", requiredPermissions),
            grantedPermissions.Count == 0 ? "(none)" : string.Join(",", grantedPermissions));
    }

    private async Task DenyAsync(
        AuthorizationHandlerContext authorizationContext,
        HttpContext httpContext,
        int statusCode,
        string error,
        string message)
    {
        await WriteErrorResponseAsync(httpContext, statusCode, error, message);
        authorizationContext.Fail(new AuthorizationFailureReason(this, message));
    }

    private static async Task WriteErrorResponseAsync(
        HttpContext httpContext,
        int statusCode,
        string error,
        string message)
    {
        if (httpContext.Response.HasStarted)
            return;

        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.ContentType = "application/json";

        await httpContext.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            error,
            message
        }));
    }

    private sealed record ScopeOwnerResolution(bool IsValid, string? SystemId, string Message)
    {
        public static ScopeOwnerResolution Valid(string systemId) => new(true, systemId, string.Empty);
        public static ScopeOwnerResolution Invalid(string message) => new(false, null, message);
    }

    private sealed record ScopeKeyResolution(bool IsValid, string? ScopeKey, string Message)
    {
        public static ScopeKeyResolution Valid(string scopeKey) => new(true, scopeKey, string.Empty);
        public static ScopeKeyResolution Invalid(string message) => new(false, null, message);
    }
}
