using System.Text.Json.Serialization;

namespace ClientDemo.Models;

public class AuthRequest
{
    [JsonPropertyName("systemId")]
    public string ClientSystemId { get; set; } = string.Empty;

    [JsonPropertyName("secret")]
    public string ClientSecret { get; set; } = string.Empty;
}

public sealed class ScopeTokenRequest
{
    [JsonPropertyName("requestedSystems")]
    public required Dictionary<string, string[]> RequestedSystems { get; init; }
}

public class AuthResponse
{
    [JsonPropertyName("result")]
    public bool Result { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("systemId")]
    public string ClientSystemId { get; set; } = string.Empty;

    [JsonPropertyName("accessToken")]
    public string AccessToken { get; set; } = string.Empty;
}

public class Country
{
    [JsonPropertyName("id")]
    public int Id { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;
}
