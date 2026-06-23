namespace ClientDemo.Services;

public interface IBlikonTokenProvider
{
    Task<string> GetTokenAsync(CancellationToken cancellationToken = default);
}
