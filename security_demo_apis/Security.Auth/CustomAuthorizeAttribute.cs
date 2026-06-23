using Microsoft.AspNetCore.Authorization;

namespace Security.Auth;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public class CustomAuthorizeAttribute : AuthorizeAttribute, IAuthorizationRequirement, IAuthorizationRequirementData
{
    public string? Permission { get; }

    public CustomAuthorizeAttribute(string? permission = null)
    {
        Permission = permission;
    }

    public IEnumerable<IAuthorizationRequirement> GetRequirements()
    {
        yield return this;
    }
}
