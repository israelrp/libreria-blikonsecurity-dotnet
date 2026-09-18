using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace Security.Auth.Tests;

[TestFixture]
public sealed class SecurityIdentityTests
{
    private static readonly Guid UserId = Guid.NewGuid();
    private static readonly Guid SystemId = Guid.NewGuid();

    private static ClaimsIdentity Identity(string? type, string? userId = null,
        string? systemId = null, string? scheme = "Bearer")
    {
        var claims = new List<Claim>();
        if (type is not null) claims.Add(new Claim("typ", type));
        if (userId is not null) claims.Add(new Claim("blikon_id", userId));
        if (systemId is not null) claims.Add(new Claim("system_id", systemId));
        return new ClaimsIdentity(claims, scheme);
    }

    private static SecurityIdentity Read(params ClaimsIdentity[] identities) =>
        new(new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(identities) }
        });

    [TestCase("user", SecurityIdentityType.User)]
    [TestCase("system", SecurityIdentityType.System)]
    [TestCase("other", SecurityIdentityType.Unknown)]
    [TestCase(null, SecurityIdentityType.Unknown)]
    public void ExponeSoloElIdentificadorDelTipoDeclarado(string? type, SecurityIdentityType expected)
    {
        var subject = Read(Identity(type, UserId.ToString(), SystemId.ToString()));
        Assert.Multiple(() =>
        {
            Assert.That(subject.IsAuthenticated, Is.True);
            Assert.That(subject.Type, Is.EqualTo(expected));
            Assert.That(subject.BlikonId, Is.EqualTo(expected == SecurityIdentityType.User ? (Guid?)UserId : null));
            Assert.That(subject.SystemId, Is.EqualTo(expected == SecurityIdentityType.System ? (Guid?)SystemId : null));
        });
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("invalid")]
    [TestCase("00000000-0000-0000-0000-000000000000")]
    public void IdentificadorAusenteOInvalido_NoRechazaAutenticacion(string? id)
    {
        var user = Read(Identity("user", id));
        Assert.That(user.IsAuthenticated, Is.True);
        Assert.That(user.BlikonId, Is.Null);
        var system = Read(Identity("system", systemId: id));
        Assert.That(system.SystemId, Is.Null);
    }

    [TestCase(null)]
    [TestCase("LegacyBearer")]
    public void IgnoraClaimsAnonimosYDeOtrosEsquemas(string? scheme)
    {
        var subject = Read(Identity("user", UserId.ToString(), scheme: scheme));
        Assert.That(subject.IsAuthenticated, Is.False);
        Assert.That(subject.Type, Is.EqualTo(SecurityIdentityType.Unknown));
        Assert.That(subject.BlikonId, Is.Null);
    }

    [Test]
    public void NoMezclaClaimsDeDistintasIdentidades()
    {
        var subject = Read(Identity("user", UserId.ToString(), scheme: "LegacyBearer"),
            Identity("system", systemId: SystemId.ToString()));
        Assert.That(subject.Type, Is.EqualTo(SecurityIdentityType.System));
        Assert.That(subject.BlikonId, Is.Null);
        Assert.That(subject.SystemId, Is.EqualTo(SystemId));
    }

    [Test]
    public void ClaimsEIdentidadesAmbiguos_NoEligeArbitrariamente()
    {
        var identity = Identity("user", UserId.ToString());
        identity.AddClaim(new Claim("blikon_id", SystemId.ToString()));
        Assert.That(Read(identity).BlikonId, Is.Null);
        identity.AddClaim(new Claim("typ", "system"));
        Assert.That(Read(identity).Type, Is.EqualTo(SecurityIdentityType.Unknown));
        Assert.That(Read(identity, Identity("user")).IsAuthenticated, Is.False);
    }

    [Test]
    public void LeeLaIdentidadDespuesDeAutenticarYSinCapturarLaPeticion()
    {
        var accessor = new HttpContextAccessor();
        accessor.HttpContext = null;
        var subject = new SecurityIdentity(accessor);
        Assert.That(subject.IsAuthenticated, Is.False);
        accessor.HttpContext = new DefaultHttpContext();
        Assert.That(subject.Type, Is.EqualTo(SecurityIdentityType.Unknown));
        accessor.HttpContext.User = new ClaimsPrincipal(Identity("user", UserId.ToString()));
        Assert.That(subject.BlikonId, Is.EqualTo(UserId));
        accessor.HttpContext = null;
        Assert.That(subject.BlikonId, Is.Null);
    }

    [TestCase(true)]
    [TestCase(false)]
    public void RegistroExistenteExponeServicioPorPeticion(bool useAsDefault)
    {
        var services = new ServiceCollection();
        services.AddCustomTokenAuth(new ConfigurationBuilder().Build(), useAsDefault);
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();
        var identity = first.ServiceProvider.GetRequiredService<ISecurityIdentity>();
        Assert.That(first.ServiceProvider.GetRequiredService<ISecurityIdentity>(), Is.SameAs(identity));
        Assert.That(second.ServiceProvider.GetRequiredService<ISecurityIdentity>(), Is.Not.SameAs(identity));
    }

    [Test]
    public async Task PeticionesConcurrentes_NoCompartenIdentidad()
    {
        var accessor = new HttpContextAccessor();
        accessor.HttpContext = null;
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var count = 0;
        async Task Check(Guid id)
        {
            accessor.HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(Identity("user", id.ToString()))
            };
            var subject = new SecurityIdentity(accessor);
            if (Interlocked.Increment(ref count) == 2) ready.SetResult();
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.That(subject.BlikonId, Is.EqualTo(id));
            accessor.HttpContext = null;
        }
        await Task.WhenAll(Task.Run(() => Check(UserId)), Task.Run(() => Check(SystemId)));
    }
}
