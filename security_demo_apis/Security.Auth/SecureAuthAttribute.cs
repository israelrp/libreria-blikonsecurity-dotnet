using Microsoft.AspNetCore.Authorization;

namespace Security.Auth;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class SecureAuthAttribute : AuthorizeAttribute, IAuthorizationRequirement, IAuthorizationRequirementData
{
    public SecureAuthAttribute(string scopeKey, string permission)
    {
        ScopeKey = scopeKey;
        Permission = permission;
    }

    public SecureAuthAttribute(string scopeOwner, string scopeKey, string permission)
    {
        ScopeOwner = scopeOwner;
        ScopeKey = scopeKey;
        Permission = permission;
    }

    public string? ScopeOwner { get; }
    public string ScopeKey { get; }
    public string Permission { get; }

    public IEnumerable<IAuthorizationRequirement> GetRequirements()
    {
        yield return this;
    }
}
