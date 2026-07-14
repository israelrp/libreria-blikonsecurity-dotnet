using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NUnit.Framework;

namespace Security.Auth.Tests;

[TestFixture]
public sealed class SecurityAuthOptionsValidationTests
{
    private const string ConsumerSystemId = "c1f93345-201e-45ba-b36a-fd2085b07b64";

    [TestCase("DeveloperSystem", "57eb7549-aad1-4063-8996-7487e250f87d")]
    [TestCase("developer-system", "not-a-guid")]
    [TestCase("developer-system", ConsumerSystemId)]
    public void ScopeOwnerInvalido_FallaValidacionDeOpciones(string alias, string ownerId)
    {
        using var provider = BuildProvider(alias, ownerId);

        Assert.Throws<OptionsValidationException>(() =>
            _ = provider.GetRequiredService<IOptions<SecurityAuthOptions>>().Value);
    }

    [Test]
    public void ScopeOwnerValido_PasaValidacionDeOpciones()
    {
        using var provider = BuildProvider(
            "developer-system",
            "57eb7549-aad1-4063-8996-7487e250f87d");

        var options = provider.GetRequiredService<IOptions<SecurityAuthOptions>>().Value;

        Assert.That(options.ScopeOwners["developer-system"],
            Is.EqualTo("57eb7549-aad1-4063-8996-7487e250f87d"));
    }

    private static ServiceProvider BuildProvider(string alias, string ownerId)
    {
        var values = new Dictionary<string, string?>
        {
            ["Security:Auth:PublicKeyPath"] = "Auth/public_key.pem",
            ["Security:Auth:SystemId"] = ConsumerSystemId,
            ["Security:Auth:ValidIssuer"] = "https://auth.blikon.com",
            ["Security:Auth:ValidAudience"] = ConsumerSystemId,
            [$"Security:Auth:ScopeOwners:{alias}"] = ownerId
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();

        var services = new ServiceCollection();
        services.AddCustomTokenAuth(configuration);
        return services.BuildServiceProvider();
    }
}
