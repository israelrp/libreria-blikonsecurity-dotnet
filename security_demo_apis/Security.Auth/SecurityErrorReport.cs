namespace Security.Auth;

public sealed class SecurityErrorReport
{
    public string ExceptionType { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string Criticality { get; set; } = "critical";
    public string Traceback { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FunctionName { get; set; } = string.Empty;
    public int? LineNumber { get; set; }
    public string Endpoint { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public int? StatusCode { get; set; }
    public Dictionary<string, object?> AdditionalInfo { get; set; } = new();
}
