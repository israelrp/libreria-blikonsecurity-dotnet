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
            await errorReporter.ReportAsync(ex, httpContext);

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
}
