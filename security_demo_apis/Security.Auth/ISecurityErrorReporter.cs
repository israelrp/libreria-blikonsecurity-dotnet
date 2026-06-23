namespace Security.Auth;

public interface ISecurityErrorReporter
{
    Task ReportAsync(SecurityErrorReport report, CancellationToken cancellationToken = default);
}
