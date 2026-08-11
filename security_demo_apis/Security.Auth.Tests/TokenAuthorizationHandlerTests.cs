using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace Security.Auth.Tests;

[TestFixture]
public sealed class TokenAuthorizationHandlerTests
{
    private const string BlikonId = "3da284b8-311a-4e8f-b228-41086bac4e46";
    private const string Issuer = "https://auth.blikon.com";
    private const string ConsumerSystemId = "c1f93345-201e-45ba-b36a-fd2085b07b64";
    private const string DeveloperSystemId = "57eb7549-aad1-4063-8996-7487e250f87d";
    private const string GatewayAudience = "8d3d1510-bda7-44bb-b822-3e164a5818a8";

    private RSA _rsa = null!;
    private string _publicKeyPath = null!;

    [SetUp]
    public void SetUp()
    {
        _rsa = RSA.Create(2048);
        _publicKeyPath = Path.GetTempFileName();
        File.WriteAllText(_publicKeyPath, _rsa.ExportSubjectPublicKeyInfoPem());
    }

    [TearDown]
    public void TearDown()
    {
        _rsa.Dispose();
        if (File.Exists(_publicKeyPath))
            File.Delete(_publicKeyPath);
    }

    [Test]
    public async Task ConstructorCorto_AutorizaScopeDelSistemaConsumidor()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("system", "systems.update"),
            [ConsumerSystemId],
            Scopes((ConsumerSystemId, "system", new[] { "systems.update" })));

        Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
    }

    [Test]
    public async Task TokenValido_ExponeBlikonIdEnPrincipalAutenticado()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("system", "systems.update"),
            [ConsumerSystemId],
            Scopes((ConsumerSystemId, "system", new[] { "systems.update" })));

        Assert.Multiple(() =>
        {
            Assert.That(result.AuthorizationContext.User.Identity?.IsAuthenticated, Is.True);
            Assert.That(
                result.AuthorizationContext.User.FindFirst("blikon_id")?.Value,
                Is.EqualTo(BlikonId));
        });
    }

    [Test]
    public async Task ConstructorLargo_AutorizaScopeDeSistemaExterno()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "dev-account.2", "develop.write"),
            [DeveloperSystemId],
            Scopes((DeveloperSystemId, "dev-account.2", new[] { "develop.write" })));

        Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
    }

    [Test]
    public async Task SistemaConsumidorAusenteDeAudience_RechazaSinIniciarRespuesta()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("system", "systems.update"),
            [GatewayAudience],
            Scopes((ConsumerSystemId, "system", new[] { "systems.update" })),
            validAudience: GatewayAudience);

        Assert.Multiple(() =>
        {
            Assert.That(result.AuthorizationContext.HasFailed, Is.True);
            Assert.That(result.HttpContext.Response.Body.Length, Is.Zero);
        });
    }

    [Test]
    public async Task PropietarioExternoAusenteDeAudience_RechazaAunqueExistaEnScopes()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "dev-account.2", "develop.write"),
            [ConsumerSystemId],
            Scopes((DeveloperSystemId, "dev-account.2", new[] { "develop.write" })),
            validAudience: ConsumerSystemId);

        Assert.Multiple(() =>
        {
            Assert.That(result.AuthorizationContext.HasFailed, Is.True);
            Assert.That(result.HttpContext.Response.Body.Length, Is.Zero);
        });
    }

    [Test]
    public async Task AliasDesconocido_RechazaAutorizacion()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("unknown-system", "resource.1", "resource.read"),
            [ConsumerSystemId],
            new());

        Assert.That(result.AuthorizationContext.HasFailed, Is.True);
    }

    [Test]
    public async Task FirmaInvalida_RechazaAutenticacion()
    {
        using var otherRsa = RSA.Create(2048);
        var result = await AuthorizeAsync(
            [new SecureAuthAttribute("system", "systems.update")],
            [ConsumerSystemId],
            Scopes((ConsumerSystemId, "system", new[] { "systems.update" })),
            signingKey: otherRsa);

        Assert.That(result.AuthorizationContext.HasFailed, Is.True);
    }

    [Test]
    public async Task PermisoAusente_RechazaAutorizacion()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("system", "systems.delete"),
            [ConsumerSystemId],
            Scopes((ConsumerSystemId, "system", new[] { "systems.read" })));

        Assert.That(result.AuthorizationContext.HasFailed, Is.True);
    }

    [TestCase("ABC-123")]
    [TestCase("3da284b8-311a-4e8f-b228-41086bac4e46")]
    [TestCase("2")]
    public async Task PlaceholderDesdeRoute_SoportaStringGuidYNumerico(string accountId)
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "dev-account.{accountId}", "develop.write"),
            [ConsumerSystemId, DeveloperSystemId],
            Scopes((DeveloperSystemId, $"dev-account.{accountId}", new[] { "develop.write" })),
            configureRequest: context => context.Request.RouteValues["accountId"] = accountId);

        Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
    }

    [Test]
    public async Task PlaceholderUsaPrecedenciaRouteQueryBody()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "dev-account.{accountId}", "develop.write"),
            [ConsumerSystemId, DeveloperSystemId],
            Scopes((DeveloperSystemId, "dev-account.route-value", new[] { "develop.write" })),
            configureRequest: context =>
            {
                context.Request.RouteValues["accountId"] = "route-value";
                context.Request.QueryString = new QueryString("?accountId=query-value");
                SetJsonBody(context, """{"accountId":"body-value"}""");
            });

        Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
    }

    [Test]
    public async Task PlaceholderDesdeBody_AutorizaYRestauraElStream()
    {
        const string json = """{"accountId":"body-account"}""";
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "dev-account.{accountId}", "develop.write"),
            [ConsumerSystemId, DeveloperSystemId],
            Scopes((DeveloperSystemId, "dev-account.body-account", new[] { "develop.write" })),
            configureRequest: context => SetJsonBody(context, json));

        using var reader = new StreamReader(result.HttpContext.Request.Body, Encoding.UTF8, leaveOpen: true);
        var bodyAfterAuthorization = await reader.ReadToEndAsync();

        Assert.Multiple(() =>
        {
            Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
            Assert.That(bodyAfterAuthorization, Is.EqualTo(json));
        });
    }

    [Test]
    public async Task PropiedadAnidadaEnBody_NoSeResuelveYRechazaAutorizacion()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "dev-account.{accountId}", "develop.write"),
            [ConsumerSystemId, DeveloperSystemId],
            Scopes((DeveloperSystemId, "dev-account.2", new[] { "develop.write" })),
            configureRequest: context => SetJsonBody(context, """{"account":{"accountId":"2"}}"""));

        Assert.That(result.AuthorizationContext.HasFailed, Is.True);
    }

    [Test]
    public async Task VariosPlaceholders_SeResuelvenCompletamente()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "resource.{tenantId}.{resourceId}", "resource.read"),
            [ConsumerSystemId, DeveloperSystemId],
            Scopes((DeveloperSystemId, "resource.tenant-a.42", new[] { "resource.read" })),
            configureRequest: context =>
            {
                context.Request.RouteValues["tenantId"] = "tenant-a";
                context.Request.QueryString = new QueryString("?resourceId=42");
            });

        Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
    }

    [Test]
    public async Task PermisosSeparadosPorComa_UsanSemanticaOrCaseInsensitive()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "dev-account.2", "develop.write,account.changename"),
            [ConsumerSystemId, DeveloperSystemId],
            Scopes((DeveloperSystemId, "dev-account.2", new[] { "ACCOUNT.CHANGENAME" })));

        Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
    }

    [Test]
    public async Task ScopeKeyConDiferenteCasing_Autoriza()
    {
        var result = await AuthorizeAsync(
            new SecureAuthAttribute("developer-system", "dev-account.2", "develop.write"),
            [ConsumerSystemId, DeveloperSystemId],
            Scopes((DeveloperSystemId, "DEV-ACCOUNT.2", new[] { "develop.write" })));

        Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
    }

    [Test]
    public async Task VariosAtributos_UsanSemanticaAnd()
    {
        var requirements = new SecureAuthAttribute[]
        {
            new("system", "systems.read"),
            new("developer-system", "dev-account.2", "develop.write")
        };

        var result = await AuthorizeAsync(
            requirements,
            [ConsumerSystemId, DeveloperSystemId],
            Scopes(
                (ConsumerSystemId, "system", new[] { "systems.read" }),
                (DeveloperSystemId, "dev-account.2", new[] { "develop.write" })));

        Assert.That(result.AuthorizationContext.HasSucceeded, Is.True);
    }

    [Test]
    public async Task ScopeMalFormado_RechazaAutorizacion()
    {
        var result = await AuthorizeAsync(
            [new SecureAuthAttribute("system", "systems.read")],
            [ConsumerSystemId],
            scopes: null,
            rawScopeClaim: "{");

        Assert.That(result.AuthorizationContext.HasFailed, Is.True);
    }

    private Task<AuthorizationExecutionResult> AuthorizeAsync(
        SecureAuthAttribute requirement,
        IReadOnlyCollection<string> audiences,
        Dictionary<string, Dictionary<string, string[]>> scopes,
        Action<DefaultHttpContext>? configureRequest = null,
        string? validAudience = null)
    {
        return AuthorizeAsync([requirement], audiences, scopes, configureRequest, validAudience);
    }

    private async Task<AuthorizationExecutionResult> AuthorizeAsync(
        IReadOnlyCollection<SecureAuthAttribute> requirements,
        IReadOnlyCollection<string> audiences,
        Dictionary<string, Dictionary<string, string[]>>? scopes,
        Action<DefaultHttpContext>? configureRequest = null,
        string? validAudience = null,
        string? rawScopeClaim = null,
        RSA? signingKey = null)
    {
        var options = new SecurityAuthOptions
        {
            PublicKeyPath = _publicKeyPath,
            SystemId = ConsumerSystemId,
            ValidIssuer = Issuer,
            ValidAudience = validAudience ?? ConsumerSystemId,
            EnableSuperAdminBypass = false,
            ScopeOwners = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["developer-system"] = DeveloperSystemId
            }
        };

        var token = CreateToken(audiences, scopes, rawScopeClaim, signingKey);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        httpContext.Response.Body = new MemoryStream();
        configureRequest?.Invoke(httpContext);

        var accessor = new HttpContextAccessor { HttpContext = httpContext };
        var publicKeyProvider = new PublicKeyProvider(Options.Create(options));
        var handler = new TokenAuthorizationHandler(
            accessor,
            Options.Create(options),
            publicKeyProvider,
            NullLogger<TokenAuthorizationHandler>.Instance);

        var validationResult = await JwtValidator.ValidarTokenAsync(
            token,
            publicKeyProvider.PublicKeyPem,
            Issuer,
            new[] { ConsumerSystemId, DeveloperSystemId, validAudience ?? ConsumerSystemId });
        var principal = validationResult.Principal ??
            new ClaimsPrincipal(new ClaimsIdentity());
        httpContext.User = principal;

        var authorizationContext = new AuthorizationHandlerContext(
            requirements,
            principal,
            httpContext);

        await handler.HandleAsync(authorizationContext);
        return new AuthorizationExecutionResult(authorizationContext, httpContext);
    }

    private string CreateToken(
        IReadOnlyCollection<string> audiences,
        Dictionary<string, Dictionary<string, string[]>>? scopes,
        string? rawScopeClaim,
        RSA? signingKey)
    {
        var claims = new Dictionary<string, object>
        {
            ["is_superadmin"] = false,
            ["blikon_id"] = BlikonId
        };

        if (rawScopeClaim is not null)
            claims["scp"] = rawScopeClaim;
        else if (scopes is not null)
            claims["scp"] = JsonSerializer.SerializeToElement(scopes);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            IssuedAt = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(signingKey ?? _rsa),
                SecurityAlgorithms.RsaSha256)
        };

        foreach (var audience in audiences)
            descriptor.Audiences.Add(audience);

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static Dictionary<string, Dictionary<string, string[]>> Scopes(
        params (string OwnerId, string ScopeKey, string[] Permissions)[] entries)
    {
        var scopes = new Dictionary<string, Dictionary<string, string[]>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (!scopes.TryGetValue(entry.OwnerId, out var ownerScopes))
            {
                ownerScopes = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                scopes[entry.OwnerId] = ownerScopes;
            }

            ownerScopes[entry.ScopeKey] = entry.Permissions;
        }

        return scopes;
    }

    private static void SetJsonBody(DefaultHttpContext context, string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;
        context.Request.ContentType = "application/json";
    }

    private sealed record AuthorizationExecutionResult(
        AuthorizationHandlerContext AuthorizationContext,
        DefaultHttpContext HttpContext);
}
