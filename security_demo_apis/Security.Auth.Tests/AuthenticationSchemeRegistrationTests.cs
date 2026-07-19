using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NUnit.Framework;

namespace Security.Auth.Tests;

[TestFixture]
public sealed class AuthenticationSchemeRegistrationTests
{
    private const string LegacyScheme = "LegacyBearer";

    [Test]
    public async Task RegistroPredeterminado_ConfiguraYRegistraBearer()
    {
        using var provider = BuildProvider(useAsDefault: true);

        var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
        var schemeProvider = provider.GetRequiredService<IAuthenticationSchemeProvider>();
        var scheme = await schemeProvider.GetSchemeAsync(SecurityAuthDefaults.AuthenticationScheme);

        Assert.Multiple(() =>
        {
            Assert.That(options.DefaultAuthenticateScheme, Is.EqualTo(SecurityAuthDefaults.AuthenticationScheme));
            Assert.That(options.DefaultChallengeScheme, Is.EqualTo(SecurityAuthDefaults.AuthenticationScheme));
            Assert.That(options.DefaultForbidScheme, Is.EqualTo(SecurityAuthDefaults.AuthenticationScheme));
            Assert.That(scheme, Is.Not.Null);
        });
    }

    [Test]
    public async Task RegistroNoPredeterminado_ConservaEsquemaExistenteYRegistraBearer()
    {
        using var provider = BuildProvider(useAsDefault: false);

        var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
        var schemeProvider = provider.GetRequiredService<IAuthenticationSchemeProvider>();
        var scheme = await schemeProvider.GetSchemeAsync(SecurityAuthDefaults.AuthenticationScheme);

        Assert.Multiple(() =>
        {
            Assert.That(options.DefaultAuthenticateScheme, Is.EqualTo(LegacyScheme));
            Assert.That(options.DefaultChallengeScheme, Is.EqualTo(LegacyScheme));
            Assert.That(options.DefaultForbidScheme, Is.EqualTo(LegacyScheme));
            Assert.That(scheme, Is.Not.Null);
        });
    }

    [Test]
    public void SecureAuth_SeleccionaBearerEnAmbosConstructores()
    {
        var shortAttribute = new SecureAuthAttribute("system", "systems.read");
        var longAttribute = new SecureAuthAttribute("developer-system", "dev-account.2", "develop.read");

        Assert.Multiple(() =>
        {
            Assert.That(shortAttribute.AuthenticationSchemes, Is.EqualTo(SecurityAuthDefaults.AuthenticationScheme));
            Assert.That(longAttribute.AuthenticationSchemes, Is.EqualTo(SecurityAuthDefaults.AuthenticationScheme));
        });
    }

    private static ServiceProvider BuildProvider(bool useAsDefault)
    {
        var configuration = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = LegacyScheme;
            options.DefaultChallengeScheme = LegacyScheme;
            options.DefaultForbidScheme = LegacyScheme;
        });
        services.AddCustomTokenAuth(configuration, useAsDefault);

        return services.BuildServiceProvider();
    }
}
