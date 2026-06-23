using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace Security.Auth;

public class NoOpAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public NoOpAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var identity = new ClaimsIdentity("Bearer");
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), "Bearer");
        return Task.FromResult(AuthenticateResult.Success(ticket));
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
