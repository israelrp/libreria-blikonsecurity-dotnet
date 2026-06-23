using System.Net;

namespace ClientDemo.Services;

public sealed class ProtectedApiException : HttpRequestException
{
    public ProtectedApiException(HttpStatusCode statusCode, string? reasonPhrase, string responseBody)
        : base($"The protected API returned {(int)statusCode} ({reasonPhrase}).", null, statusCode)
    {
        ResponseBody = responseBody;
    }

    public string ResponseBody { get; }
}
