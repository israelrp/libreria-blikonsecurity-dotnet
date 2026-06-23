namespace ClientDemo.Options;

public sealed class BlikonSecurityOptions
{
    public const string SectionName = "BlikonSecurity";

    public required string SecurityBaseUrl { get; init; }
    public required string LoginEndpoint { get; init; }
    public required string TokenEndpoint { get; init; }
    public required string ClientSystemId { get; init; }
    public required string ClientSecret { get; init; }
    public required string TargetSystemId { get; init; }
    public int TokenRefreshSkewSeconds { get; init; } = 60;
    public int FallbackTokenLifetimeSeconds { get; init; } = 300;
}
