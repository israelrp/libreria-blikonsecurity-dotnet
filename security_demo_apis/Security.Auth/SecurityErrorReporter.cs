using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Security.Auth;

internal sealed class SecurityErrorReporter : ISecurityErrorReporter
{
    private const int MaxErrorMessageLength = 300;

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

    public Task ReportAsync(
        Exception exception,
        HttpContext? httpContext = null,
        string? criticality = null,
        int? statusCode = null,
        IDictionary<string, object?>? additionalInfo = null,
        CancellationToken cancellationToken = default)
    {
        var resolvedStatusCode = statusCode ?? StatusCodes.Status500InternalServerError;
        var report = BuildReport(exception, httpContext, criticality, resolvedStatusCode, additionalInfo);

        if (cancellationToken == default && httpContext is not null)
            cancellationToken = httpContext.RequestAborted;

        return ReportAsync(report, cancellationToken);
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

        report.ErrorMessage = NormalizeText(report.ErrorMessage, MaxErrorMessageLength);

        if (string.IsNullOrWhiteSpace(report.Criticality))
            throw new ArgumentException("Criticality es requerido.", nameof(report));

        report.Criticality = SecurityErrorCriticality.Normalize(report.Criticality);
    }

    private static SecurityErrorReport BuildReport(
        Exception exception,
        HttpContext? httpContext,
        string? criticality,
        int statusCode,
        IDictionary<string, object?>? additionalInfo)
    {
        var stackFrame = GetFirstStackFrame(exception);
        var request = httpContext?.Request;
        var reportAdditionalInfo = BuildAdditionalInfo(httpContext);

        if (additionalInfo is not null)
        {
            foreach (var item in additionalInfo)
            {
                reportAdditionalInfo[item.Key] = item.Value;
            }
        }

        return new SecurityErrorReport
        {
            ExceptionType = exception.GetType().Name,
            ErrorMessage = exception.Message,
            Criticality = criticality ?? SecurityErrorCriticality.FromException(exception, statusCode),
            Traceback = exception.ToString(),
            FileName = NormalizeText(Path.GetFileName(stackFrame?.GetFileName()), 100),
            FunctionName = NormalizeText(stackFrame?.GetMethod()?.Name, 100),
            LineNumber = GetLineNumber(stackFrame),
            Endpoint = request?.Path.Value ?? string.Empty,
            Method = request?.Method ?? string.Empty,
            StatusCode = statusCode,
            AdditionalInfo = reportAdditionalInfo
        };
    }

    private static Dictionary<string, object?> BuildAdditionalInfo(HttpContext? httpContext)
    {
        var additionalInfo = new Dictionary<string, object?>
        {
            ["actorType"] = "system"
        };

        if (httpContext is null)
            return additionalInfo;

        var request = httpContext.Request;
        additionalInfo["requestId"] = httpContext.TraceIdentifier;
        additionalInfo["traceIdentifier"] = httpContext.TraceIdentifier;
        additionalInfo["path"] = request.Path.Value;
        additionalInfo["queryString"] = request.QueryString.Value;
        additionalInfo["host"] = request.Host.Value;

        return additionalInfo;
    }

    private static StackFrame? GetFirstStackFrame(Exception exception)
    {
        return new StackTrace(exception, true)
            .GetFrames()?
            .FirstOrDefault(frame => frame.GetMethod() is not null);
    }

    private static int? GetLineNumber(StackFrame? stackFrame)
    {
        var lineNumber = stackFrame?.GetFileLineNumber() ?? 0;
        return lineNumber > 0 ? lineNumber : null;
    }

    private static string NormalizeText(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        return value.Length <= maxLength ? value : value[..maxLength];
    }
}
