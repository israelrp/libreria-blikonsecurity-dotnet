namespace ClientDemo.Options;

public sealed class ProtectedApiOptions
{
    public const string SectionName = "ProtectedApi";

    public required string BaseUrl { get; init; }
}
