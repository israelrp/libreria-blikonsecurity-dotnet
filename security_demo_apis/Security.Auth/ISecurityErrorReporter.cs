using Microsoft.AspNetCore.Http;

namespace Security.Auth;

public interface ISecurityErrorReporter
{
    Task ReportAsync(SecurityErrorReport report, CancellationToken cancellationToken = default);

    Task ReportAsync(
        Exception exception,
        HttpContext? httpContext = null,
        string? criticality = null,
        int? statusCode = null,
        IDictionary<string, object?>? additionalInfo = null,
        CancellationToken cancellationToken = default);
}
