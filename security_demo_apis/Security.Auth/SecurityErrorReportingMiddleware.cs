using System.Diagnostics;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Security.Auth;

public sealed class SecurityErrorReportingMiddleware
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityErrorReportingMiddleware> _logger;

    public SecurityErrorReportingMiddleware(
        RequestDelegate next,
        ILogger<SecurityErrorReportingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext httpContext, ISecurityErrorReporter errorReporter)
    {
        try
        {
            await _next(httpContext);
        }
        catch (Exception ex)
        {
            await ReportExceptionAsync(httpContext, errorReporter, ex);

            if (httpContext.Response.HasStarted)
            {
                _logger.LogWarning("No se puede escribir respuesta 500 porque la respuesta ya inicio.");
                throw;
            }

            httpContext.Response.Clear();
            httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
            httpContext.Response.ContentType = "application/json";

            await httpContext.Response.WriteAsync(JsonSerializer.Serialize(new
            {
                error = "internal_server_error",
                message = "Error interno del servidor."
            }, JsonOptions));
        }
    }

    private static async Task ReportExceptionAsync(
        HttpContext httpContext,
        ISecurityErrorReporter errorReporter,
        Exception exception)
    {
        var stackFrame = GetFirstStackFrame(exception);
        var request = httpContext.Request;

        var report = new SecurityErrorReport
        {
            ExceptionType = exception.GetType().Name,
            ErrorMessage = exception.Message,
            Criticality = "critical",
            Traceback = exception.ToString(),
            FileName = NormalizeText(Path.GetFileName(stackFrame?.GetFileName()), 100),
            FunctionName = NormalizeText(stackFrame?.GetMethod()?.Name, 100),
            LineNumber = GetLineNumber(stackFrame),
            Endpoint = request.Path.Value ?? string.Empty,
            Method = request.Method,
            StatusCode = StatusCodes.Status500InternalServerError,
            AdditionalInfo = new Dictionary<string, object?>
            {
                ["actorType"] = "system",
                ["requestId"] = httpContext.TraceIdentifier,
                ["traceIdentifier"] = httpContext.TraceIdentifier,
                ["path"] = request.Path.Value,
                ["queryString"] = request.QueryString.Value,
                ["host"] = request.Host.Value
            }
        };

        await errorReporter.ReportAsync(report, httpContext.RequestAborted);
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
