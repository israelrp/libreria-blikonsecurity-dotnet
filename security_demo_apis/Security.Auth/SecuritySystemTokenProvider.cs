using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Security.Auth;

internal sealed class SecuritySystemTokenProvider : ISecuritySystemTokenProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly SecurityAuthOptions _authOptions;
    private readonly SecurityErrorOptions _errorOptions;
    private readonly ILogger<SecuritySystemTokenProvider> _logger;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private string? _accessToken;

    public SecuritySystemTokenProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<SecurityAuthOptions> authOptions,
        IOptions<SecurityErrorOptions> errorOptions,
        ILogger<SecuritySystemTokenProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _authOptions = authOptions.Value;
        _errorOptions = errorOptions.Value;
        _logger = logger;
    }

    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(_accessToken))
            return _accessToken;

        await _tokenLock.WaitAsync(cancellationToken);
        try
        {
            if (!string.IsNullOrWhiteSpace(_accessToken))
                return _accessToken;

            ValidateOptions();

            var client = _httpClientFactory.CreateClient(SecurityHttpClientNames.ErrorReporting);
            var requestUri = new Uri(client.BaseAddress!, "auth/systems");
            _logger.LogInformation("Autenticando sistema para registrar errores. Url: {Url}", requestUri);

            var response = await client.PostAsJsonAsync(
                requestUri,
                new AuthenticateSystemRequest(_authOptions.SystemId, _errorOptions.Secret),
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                throw new InvalidOperationException(
                    $"No fue posible autenticar el sistema para registrar errores. Url: {requestUri}. StatusCode: {(int)response.StatusCode}. Response: {body}");
            }

            var payload = await response.Content.ReadFromJsonAsync<AuthenticateSystemResponse>(cancellationToken);
            if (payload is null || string.IsNullOrWhiteSpace(payload.AccessToken))
                throw new InvalidOperationException("La respuesta de /auth/systems no contiene accessToken.");

            _accessToken = payload.AccessToken;
            return _accessToken;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error autenticando el sistema para registrar errores.");
            throw;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    public void InvalidateToken()
    {
        _accessToken = null;
    }

    private void ValidateOptions()
    {
        if (string.IsNullOrWhiteSpace(_authOptions.SystemId))
            throw new InvalidOperationException("Security:Auth:SystemId no esta configurado.");

        if (string.IsNullOrWhiteSpace(_errorOptions.Secret))
            throw new InvalidOperationException("Security:Errors:Secret no esta configurado.");
    }

    private sealed record AuthenticateSystemRequest(
        [property: JsonPropertyName("systemId")] string SystemId,
        [property: JsonPropertyName("secret")] string Secret);

    private sealed class AuthenticateSystemResponse
    {
        [JsonPropertyName("result")]
        public bool Result { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonPropertyName("systemId")]
        public string? SystemId { get; set; }

        [JsonPropertyName("accessToken")]
        public string? AccessToken { get; set; }
    }
}
