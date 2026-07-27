using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace Security.Auth;

public sealed class SecurityTokenAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly SecurityAuthOptions _authOptions;
    private readonly PublicKeyProvider _publicKeyProvider;

    public SecurityTokenAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IOptions<SecurityAuthOptions> authOptions,
        PublicKeyProvider publicKeyProvider) : base(options, logger, encoder)
    {
        _authOptions = authOptions.Value;
        _publicKeyProvider = publicKeyProvider;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authorizationValues))
            return AuthenticateResult.NoResult();

        var authorization = authorizationValues.ToString();
        if (string.IsNullOrWhiteSpace(authorization) ||
            !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var token = authorization["Bearer ".Length..].Trim();
        if (token.Length == 0)
            return AuthenticateResult.Fail("Token no proporcionado.");

        var validAudiences = new[]
            {
                _authOptions.ValidAudience,
                _authOptions.SystemId
            }
            .Concat(_authOptions.ScopeOwners.Values)
            .Where(audience => !string.IsNullOrWhiteSpace(audience))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var validationResult = await JwtValidator.ValidarTokenAsync(
            token,
            _publicKeyProvider.PublicKeyPem,
            _authOptions.ValidIssuer,
            validAudiences);

        if (!validationResult.IsValid || validationResult.Principal is null)
            return AuthenticateResult.Fail(validationResult.ErrorMessage ?? "Token invalido.");

        var ticket = new AuthenticationTicket(
            validationResult.Principal,
            SecurityAuthDefaults.AuthenticationScheme);
        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (Response.HasStarted)
            return Task.CompletedTask;

        Response.StatusCode = 401;
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        if (Response.HasStarted)
            return Task.CompletedTask;

        Response.StatusCode = 403;
        return Task.CompletedTask;
    }
}
