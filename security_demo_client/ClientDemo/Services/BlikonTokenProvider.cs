using System.Text.Json;
using ClientDemo.Options;
using Microsoft.Extensions.Options;

namespace ClientDemo.Services;

public sealed class BlikonTokenProvider : IBlikonTokenProvider, IDisposable
{
    private readonly IBlikonSecurityClient _securityClient;
    private readonly BlikonSecurityOptions _options;
    private readonly ILogger<BlikonTokenProvider> _logger;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private string? _token;
    private DateTimeOffset _expiresAt;

    public BlikonTokenProvider(
        IBlikonSecurityClient securityClient,
        IOptions<BlikonSecurityOptions> options,
        ILogger<BlikonTokenProvider> logger)
    {
        _securityClient = securityClient;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        if (IsValid()) return _token!;

        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            if (IsValid()) return _token!;

            var accessToken = await _securityClient.AuthenticateAsync(cancellationToken);
            _token = await _securityClient.RequestScopeTokenAsync(accessToken, cancellationToken);
            _expiresAt = GetExpiration(_token)
                ?? DateTimeOffset.UtcNow.AddSeconds(_options.FallbackTokenLifetimeSeconds);

            _logger.LogDebug("Scope token refreshed; cached until {ExpiresAt}.", _expiresAt);
            return _token;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private bool IsValid() =>
        !string.IsNullOrWhiteSpace(_token) &&
        _expiresAt > DateTimeOffset.UtcNow.AddSeconds(_options.TokenRefreshSkewSeconds);

    private static DateTimeOffset? GetExpiration(string jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length < 2) return null;

            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
            using var json = JsonDocument.Parse(Convert.FromBase64String(payload));
            return json.RootElement.TryGetProperty("exp", out var exp)
                ? DateTimeOffset.FromUnixTimeSeconds(exp.GetInt64())
                : null;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    public void Dispose() => _refreshLock.Dispose();
}
