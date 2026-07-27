using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace ClientDemo.Services;

public sealed class ProtectedApiClient : IProtectedApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly HttpClient _httpClient;
    private readonly IBlikonTokenProvider _tokenProvider;
    private readonly ILogger<ProtectedApiClient> _logger;

    public ProtectedApiClient(
        HttpClient httpClient,
        IBlikonTokenProvider tokenProvider,
        ILogger<ProtectedApiClient> logger)
    {
        _httpClient = httpClient;
        _tokenProvider = tokenProvider;
        _logger = logger;
    }

    public Task<TResponse?> GetAsync<TResponse>(string requestUri, CancellationToken cancellationToken = default) =>
        SendAsync<TResponse>(HttpMethod.Get, requestUri, cancellationToken: cancellationToken);

    public Task<TResponse?> PostAsync<TRequest, TResponse>(
        string requestUri,
        TRequest body,
        CancellationToken cancellationToken = default) =>
        SendAsync<TResponse>(HttpMethod.Post, requestUri, body, cancellationToken);

    public async Task<TResponse?> SendAsync<TResponse>(
        HttpMethod method,
        string requestUri,
        object? body = null,
        CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, requestUri);
        var token = await _tokenProvider.GetTokenAsync(cancellationToken);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: JsonOptions);
        }

        _logger.LogInformation("Sending {Method} request to protected API endpoint {Endpoint}.", method, requestUri);
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogWarning(
                "Protected API request to {Endpoint} failed with HTTP {StatusCode}.",
                requestUri,
                (int)response.StatusCode);
            throw new ProtectedApiException(response.StatusCode, response.ReasonPhrase, errorBody);
        }

        if (response.StatusCode == System.Net.HttpStatusCode.NoContent || response.Content.Headers.ContentLength == 0)
        {
            return default;
        }

        try
        {
            return await response.Content.ReadFromJsonAsync<TResponse>(JsonOptions, cancellationToken);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"The protected API returned invalid JSON for {method} {requestUri}.", ex);
        }
    }
}
