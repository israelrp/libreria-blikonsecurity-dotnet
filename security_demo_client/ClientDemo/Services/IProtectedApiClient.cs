namespace ClientDemo.Services;

public interface IProtectedApiClient
{
    Task<TResponse?> SendAsync<TResponse>(
        HttpMethod method,
        string requestUri,
        object? body = null,
        CancellationToken cancellationToken = default);

    Task<TResponse?> GetAsync<TResponse>(string requestUri, CancellationToken cancellationToken = default);

    Task<TResponse?> PostAsync<TRequest, TResponse>(
        string requestUri,
        TRequest body,
        CancellationToken cancellationToken = default);
}
