namespace DemoAPIWithSecurity.Auth;

public sealed class AuthOptions
{
    public const string SectionName = "AuthSettings";

    public string PublicKeyPath { get; set; } = string.Empty;
    public string SystemId { get; set; } = string.Empty;
    public string ValidIssuer { get; set; } = string.Empty;
    public string ValidAudience { get; set; } = string.Empty;
}
