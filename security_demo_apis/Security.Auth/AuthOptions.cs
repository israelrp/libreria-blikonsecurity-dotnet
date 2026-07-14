namespace Security.Auth;

public sealed class SecurityAuthOptions
{
    public const string SectionName = "Security:Auth";

    public string PublicKeyPath { get; set; } = string.Empty;
    public string SystemId { get; set; } = string.Empty;
    public string ValidIssuer { get; set; } = string.Empty;
    public string ValidAudience { get; set; } = string.Empty;
    public bool EnableSuperAdminBypass { get; set; } = true;
    public Dictionary<string, string> ScopeOwners { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
