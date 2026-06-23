namespace DemoAPIWithSecurity.Auth;

public class TokenVerifyResponse
{
    public bool Result { get; set; }
    public string? Message { get; set; }
    public string? Subject { get; set; }
    public string? ActorType { get; set; }
    public List<string>? Audience { get; set; }
    public int? ExpiresIn { get; set; }
    public string? Version { get; set; }

    // { audienceId: { resourceName: [ "perm1", "perm2" ] } }
    public Dictionary<string, Dictionary<string, List<string>>>? Scopes { get; set; }

    public IEnumerable<string> GetAllPermissions() =>
        Scopes?.Values
               .SelectMany(resource => resource.Values)
               .SelectMany(perms => perms)
        ?? Enumerable.Empty<string>();
}
