namespace ClientDemo.Services;

public interface IBlikonSecurityClient
{
    Task<string> AuthenticateAsync(CancellationToken cancellationToken = default);
    Task<string> RequestScopeTokenAsync(string accessToken, CancellationToken cancellationToken = default);
}
