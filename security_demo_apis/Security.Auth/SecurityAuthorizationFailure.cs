namespace Security.Auth;

internal sealed record SecurityAuthorizationFailure(
    int StatusCode,
    string Error,
    string Message)
{
    internal static readonly object ItemKey = new();
}
