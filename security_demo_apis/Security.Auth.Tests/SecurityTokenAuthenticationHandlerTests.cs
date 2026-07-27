using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace Security.Auth.Tests;

[TestFixture]
public sealed class SecurityTokenAuthenticationHandlerTests
{
    private const string Issuer = "https://auth.blikon.com";
    private const string SystemId = "c1f93345-201e-45ba-b36a-fd2085b07b64";
    private const string ExternalSystemId = "57eb7549-aad1-4063-8996-7487e250f87d";
    private const string BlikonId = "3da284b8-311a-4e8f-b228-41086bac4e46";

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
    public async Task SinAuthorizationHeader_DevuelveNoResult()
    {
        var result = await AuthenticateAsync();

        Assert.That(result.None, Is.True);
    }

    [Test]
    public async Task TokenValido_CreaPrincipalConClaims()
    {
        var result = await AuthenticateAsync(CreateToken([SystemId]));

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Principal?.Identity?.IsAuthenticated, Is.True);
            Assert.That(result.Principal?.FindFirst("blikon_id")?.Value, Is.EqualTo(BlikonId));
        });
    }

    [Test]
    public async Task TokenParaScopeOwnerConfigurado_EsAutenticado()
    {
        var result = await AuthenticateAsync(CreateToken([ExternalSystemId]));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task TokenConFirmaInvalida_FallaAutenticacion()
    {
        using var otherRsa = RSA.Create(2048);
        var result = await AuthenticateAsync(CreateToken([SystemId], otherRsa));

        Assert.That(result.Failure, Is.Not.Null);
    }

    private async Task<AuthenticateResult> AuthenticateAsync(string? token = null)
    {
        var authOptions = new SecurityAuthOptions
        {
            PublicKeyPath = _publicKeyPath,
            SystemId = SystemId,
            ValidIssuer = Issuer,
            ValidAudience = SystemId,
            ScopeOwners = new Dictionary<string, string>
            {
                ["developer-system"] = ExternalSystemId
            }
        };

        var schemeOptions = new AuthenticationSchemeOptions();
        var handler = new SecurityTokenAuthenticationHandler(
            new StaticOptionsMonitor<AuthenticationSchemeOptions>(schemeOptions),
            NullLoggerFactory.Instance,
            System.Text.Encodings.Web.UrlEncoder.Default,
            Options.Create(authOptions),
            new PublicKeyProvider(Options.Create(authOptions)));
        var httpContext = new DefaultHttpContext();
        if (token is not null)
            httpContext.Request.Headers.Authorization = $"Bearer {token}";

        await handler.InitializeAsync(
            new AuthenticationScheme(
                SecurityAuthDefaults.AuthenticationScheme,
                SecurityAuthDefaults.AuthenticationScheme,
                typeof(SecurityTokenAuthenticationHandler)),
            httpContext);

        return await handler.AuthenticateAsync();
    }

    private string CreateToken(IReadOnlyCollection<string> audiences, RSA? signingKey = null)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            IssuedAt = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object>
            {
                ["blikon_id"] = BlikonId
            },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(signingKey ?? _rsa),
                SecurityAlgorithms.RsaSha256)
        };

        foreach (var audience in audiences)
            descriptor.Audiences.Add(audience);

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private sealed class StaticOptionsMonitor<T>(T currentValue) : IOptionsMonitor<T>
    {
        public T CurrentValue { get; } = currentValue;
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
