using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace DemoAPIWithSecurity.Auth;

// Esquema mínimo que satisface DenyAnonymousAuthorizationRequirement
// sin hacer ninguna validación real — eso lo hace TokenAuthorizationHandler.
public class NoOpAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public NoOpAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Una identidad vacía con tipo de autenticación satisface DenyAnonymousAuthorizationRequirement.
        // Los claims reales y la validación del token viven en TokenAuthorizationHandler.
        var identity = new ClaimsIdentity("Bearer");
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), "Bearer");
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 401;
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 403;
        return Task.CompletedTask;
    }
}
