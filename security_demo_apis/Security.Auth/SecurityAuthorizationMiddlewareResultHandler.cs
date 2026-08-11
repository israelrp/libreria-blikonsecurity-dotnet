using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace Security.Auth;

public sealed class SecurityAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        var usesSecurityAuth = policy.Requirements.OfType<SecureAuthAttribute>().Any();
        if (authorizeResult.Succeeded || !usesSecurityAuth)
        {
            await _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
            return;
        }

        await _defaultHandler.HandleAsync(next, context, policy, authorizeResult);

        if (context.Response.HasStarted)
            return;

        var failure = context.Items.TryGetValue(SecurityAuthorizationFailure.ItemKey, out var value)
            ? value as SecurityAuthorizationFailure
            : null;

        var statusCode = failure?.StatusCode ??
            (authorizeResult.Challenged
                ? StatusCodes.Status401Unauthorized
                : StatusCodes.Status403Forbidden);
        var error = failure?.Error ??
            (statusCode == StatusCodes.Status401Unauthorized ? "unauthorized" : "forbidden");
        var message = failure?.Message ??
            authorizeResult.AuthorizationFailure?.FailureReasons.FirstOrDefault()?.Message ??
            (statusCode == StatusCodes.Status401Unauthorized
                ? "Token no autenticado."
                : "Acceso denegado.");

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";

        await context.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            error,
            message
        }, JsonOptions));
    }
}
