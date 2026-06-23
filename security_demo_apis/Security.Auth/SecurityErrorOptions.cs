namespace Security.Auth;

public sealed class SecurityErrorOptions
{
    public const string SectionName = "Security:Errors";

    public string BaseUrl { get; set; } = string.Empty;
    public string Secret { get; set; } = string.Empty;
}
