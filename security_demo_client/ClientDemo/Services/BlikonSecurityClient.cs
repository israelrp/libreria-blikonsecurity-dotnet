using System.Net.Http.Headers;
using System.Net.Http.Json;
using ClientDemo.Models;
using ClientDemo.Options;
using Microsoft.Extensions.Options;

namespace ClientDemo.Services;

public sealed class BlikonSecurityClient : IBlikonSecurityClient
{
    public const string HttpClientName = "BlikonSecurity";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly BlikonSecurityOptions _options;
    private readonly ILogger<BlikonSecurityClient> _logger;

    public BlikonSecurityClient(
        IHttpClientFactory httpClientFactory,
        IOptions<BlikonSecurityOptions> options,
        ILogger<BlikonSecurityClient> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<string> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        var request = new AuthRequest
        {
            ClientSystemId = _options.ClientSystemId,
            ClientSecret = _options.ClientSecret
        };

        _logger.LogDebug("Authenticating client system {ClientSystemId} with Blikon Security.", _options.ClientSystemId);
        using var response = await _httpClientFactory.CreateClient(HttpClientName)
            .PostAsJsonAsync(_options.LoginEndpoint, request, cancellationToken);

        return await ReadTokenAsync(response, "client authentication", cancellationToken);
    }

    public async Task<string> RequestScopeTokenAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var body = new ScopeTokenRequest
        {
            RequestedSystems = new Dictionary<string, string[]>
            {
                [_options.TargetSystemId] = Array.Empty<string>()
            }
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, _options.TokenEndpoint)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        _logger.LogDebug("Requesting a scope token for target system {TargetSystemId}.", _options.TargetSystemId);
        using var response = await _httpClientFactory.CreateClient(HttpClientName)
            .SendAsync(request, cancellationToken);

        return await ReadTokenAsync(response, "scope token request", cancellationToken);
    }

    private static async Task<string> ReadTokenAsync(
        HttpResponseMessage response,
        string operation,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Blikon Security {operation} failed with HTTP {(int)response.StatusCode} " +
                $"({response.ReasonPhrase}). Response: {body}");
        }

        AuthResponse? result;
        try
        {
            result = System.Text.Json.JsonSerializer.Deserialize<AuthResponse>(body,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new InvalidOperationException($"Blikon Security returned invalid JSON during {operation}.", ex);
        }

        if (result is null || !result.Result || string.IsNullOrWhiteSpace(result.AccessToken))
        {
            throw new InvalidOperationException(
                $"Blikon Security {operation} did not return a valid token. Message: {result?.Message ?? "empty response"}");
        }

        return result.AccessToken;
    }
}
