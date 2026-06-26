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

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class SystemAuthorizeAttribute : CustomAuthorizeAttribute
{
    public SystemAuthorizeAttribute(string permission) : base(permission)
    {
    }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class PlaceAuthorizeAttribute : CustomAuthorizeAttribute
{
    public PlaceAuthorizeAttribute(string permission) : base(permission)
    {
    }

    public string SpaceIdParameterName { get; set; } = "spaceId";
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class SystemOrPlaceAuthorizeAttribute : CustomAuthorizeAttribute
{
    public string? SystemPermission { get; set; }
    public string? PlacePermission { get; set; }
    public string SpaceIdParameterName { get; set; } = "spaceId";
}
