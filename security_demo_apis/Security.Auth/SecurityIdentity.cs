using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Security.Auth;

internal sealed class SecurityIdentity(IHttpContextAccessor httpContextAccessor) : ISecurityIdentity
{
    // Leer al consultar, no capturar HttpContext.User antes de autenticar.
    private ClaimsIdentity? Identity
    {
        get
        {
            var identities = httpContextAccessor.HttpContext?.User.Identities
                .Where(identity => identity.IsAuthenticated &&
                    identity.AuthenticationType == SecurityAuthDefaults.AuthenticationScheme)
                .Take(2).ToArray();
            return identities is { Length: 1 } ? identities[0] : null;
        }
    }

    public bool IsAuthenticated => Identity is not null;

    public SecurityIdentityType Type => GetType(Identity);

    public Guid? BlikonId => GetId(SecurityIdentityType.User, "blikon_id");

    public Guid? SystemId => GetId(SecurityIdentityType.System, "system_id");

    private Guid? GetId(SecurityIdentityType requiredType, string claimType)
    {
        var identity = Identity;
        return GetType(identity) == requiredType &&
            Guid.TryParse(GetClaim(identity, claimType), out var id) && id != Guid.Empty
                ? id
                : null;
    }

    private static SecurityIdentityType GetType(ClaimsIdentity? identity) =>
        GetClaim(identity, "typ") switch
        {
            "user" => SecurityIdentityType.User,
            "system" => SecurityIdentityType.System,
            _ => SecurityIdentityType.Unknown
        };

    private static string? GetClaim(ClaimsIdentity? identity, string claimType)
    {
        var claims = identity?.FindAll(claimType).Take(2).ToArray();
        return claims is { Length: 1 } ? claims[0].Value : null;
    }
}
