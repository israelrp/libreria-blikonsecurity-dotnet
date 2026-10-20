using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace Security.Auth.Tests;

[TestFixture]
public sealed class PublicKeyProviderTests
{
    [Test]
    public async Task PemConfigurado_SinArchivo_ValidaTokenFirmado()
    {
        using var rsa = RSA.Create(2048);
        const string systemId = "c1f93345-201e-45ba-b36a-fd2085b07b64";
        const string issuer = "https://auth.blikon.com";
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Security:Auth:PublicKeyPem"] = rsa.ExportSubjectPublicKeyInfoPem(),
                ["Security:Auth:PublicKeyPath"] = "missing-public-key.pem",
                ["Security:Auth:SystemId"] = systemId,
                ["Security:Auth:ValidIssuer"] = issuer,
                ["Security:Auth:ValidAudience"] = systemId
            }).Build();
        var services = new ServiceCollection();
        services.AddCustomTokenAuth(configuration);
        using var provider = services.BuildServiceProvider();
        var key = provider.GetRequiredService<PublicKeyProvider>();
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = systemId,
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
        });

        var result = await JwtValidator.ValidarTokenAsync(token, key.PublicKeyPem, issuer, systemId);

        Assert.That(result.IsValid, Is.True, result.ErrorMessage);
    }

    [TestCase("")]
    [TestCase("   ")]
    public void PemVacio_LeeArchivoLocal(string pem)
    {
        using var rsa = RSA.Create(2048);
        var path = Path.GetTempFileName();
        try
        {
            var expected = rsa.ExportSubjectPublicKeyInfoPem();
            File.WriteAllText(path, expected);
            var provider = new PublicKeyProvider(Options.Create(new SecurityAuthOptions
            {
                PublicKeyPem = pem,
                PublicKeyPath = path
            }));

            Assert.That(provider.PublicKeyPem, Is.EqualTo(expected));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public void SinLlaveConfigurada_FallaConMensajeDeConfiguracion()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new PublicKeyProvider(Options.Create(new SecurityAuthOptions())));

        Assert.That(exception!.Message, Does.Contain("PublicKeyPem").And.Contain("PublicKeyPath"));
    }

    [Test]
    public void ArchivoInexistente_FallaConFileNotFound()
    {
        Assert.Throws<FileNotFoundException>(() => new PublicKeyProvider(
            Options.Create(new SecurityAuthOptions { PublicKeyPath = $"{Guid.NewGuid()}.pem" })));
    }
}
