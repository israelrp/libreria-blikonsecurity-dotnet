namespace Security.Auth;

internal interface ISecuritySystemTokenProvider
{
    Task<string> GetAccessTokenAsync(CancellationToken cancellationToken);
    void InvalidateToken();
}
