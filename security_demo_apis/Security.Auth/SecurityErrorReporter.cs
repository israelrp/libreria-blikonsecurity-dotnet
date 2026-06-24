using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Security.Auth;

internal sealed class SecurityErrorReporter : ISecurityErrorReporter
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISecuritySystemTokenProvider _tokenProvider;
    private readonly ILogger<SecurityErrorReporter> _logger;

    public SecurityErrorReporter(
        IHttpClientFactory httpClientFactory,
        ISecuritySystemTokenProvider tokenProvider,
        ILogger<SecurityErrorReporter> logger)
    {
        _httpClientFactory = httpClientFactory;
        _tokenProvider = tokenProvider;
        _logger = logger;
    }

    public async Task ReportAsync(SecurityErrorReport report, CancellationToken cancellationToken = default)
    {
        try
        {
            ValidateReport(report);

            var response = await SendAsync(report, cancellationToken);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _tokenProvider.InvalidateToken();
                response.Dispose();
                response = await SendAsync(report, cancellationToken);
            }

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning(
                    "No fue posible registrar el error en Security API. StatusCode: {StatusCode}. Response: {Response}",
                    (int)response.StatusCode,
                    body);
            }

            response.Dispose();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error enviando reporte a Security API.");
        }
    }

    private async Task<HttpResponseMessage> SendAsync(SecurityErrorReport report, CancellationToken cancellationToken)
    {
        var token = await _tokenProvider.GetAccessTokenAsync(cancellationToken);
        var client = _httpClientFactory.CreateClient(SecurityHttpClientNames.ErrorReporting);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var requestUri = new Uri(client.BaseAddress!, "errors");
        _logger.LogInformation("Registrando error en Security API. Url: {Url}", requestUri);

        return await client.PostAsJsonAsync(requestUri, report, JsonOptions, cancellationToken);
    }

    private static void ValidateReport(SecurityErrorReport report)
    {
        if (string.IsNullOrWhiteSpace(report.ExceptionType))
            throw new ArgumentException("ExceptionType es requerido.", nameof(report));

        if (string.IsNullOrWhiteSpace(report.ErrorMessage))
            throw new ArgumentException("ErrorMessage es requerido.", nameof(report));

        if (string.IsNullOrWhiteSpace(report.Criticality))
            throw new ArgumentException("Criticality es requerido.", nameof(report));

        report.Criticality = SecurityErrorCriticality.Normalize(report.Criticality);
    }
}
