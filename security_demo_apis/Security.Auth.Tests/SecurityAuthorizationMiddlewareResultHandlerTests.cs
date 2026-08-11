using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NUnit.Framework;

namespace Security.Auth.Tests;

[TestFixture]
public sealed class SecurityAuthorizationMiddlewareResultHandlerTests
{
    [Test]
    public async Task ChallengeDeSecureAuth_Escribe401JsonUnaSolaVez()
    {
        await using var provider = BuildProvider();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = provider,
            Response = { Body = new MemoryStream() }
        };
        var requirement = new SecureAuthAttribute("system", "systems.read");
        var policy = new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(SecurityAuthDefaults.AuthenticationScheme)
            .AddRequirements(requirement)
            .Build();
        var handler = new SecurityAuthorizationMiddlewareResultHandler();

        await handler.HandleAsync(
            _ => Task.CompletedTask,
            httpContext,
            policy,
            PolicyAuthorizationResult.Challenge());

        httpContext.Response.Body.Position = 0;
        using var reader = new StreamReader(httpContext.Response.Body);
        var body = await reader.ReadToEndAsync();

        Assert.Multiple(() =>
        {
            Assert.That(httpContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status401Unauthorized));
            Assert.That(httpContext.Response.ContentType, Is.EqualTo("application/json"));
            Assert.That(body, Is.EqualTo("{\"error\":\"unauthorized\",\"message\":\"Token no autenticado.\"}"));
        });
    }

    [Test]
    public void RegistroDeSecurityAuth_ReemplazaElResultHandlerPredeterminado()
    {
        var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCustomTokenAuth(configuration);

        using var provider = services.BuildServiceProvider();

        Assert.That(
            provider.GetRequiredService<IAuthorizationMiddlewareResultHandler>(),
            Is.TypeOf<SecurityAuthorizationMiddlewareResultHandler>());
    }

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services
            .AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(
                SecurityAuthDefaults.AuthenticationScheme,
                _ => { });
        return services.BuildServiceProvider();
    }

    private sealed class TestAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public TestAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var identity = new ClaimsIdentity(Scheme.Name);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
