using Microsoft.Extensions.Options;

namespace Security.Auth;

public sealed class PublicKeyProvider
{
    public string PublicKeyPem { get; }

    public PublicKeyProvider(IOptions<SecurityAuthOptions> authOptions)
    {
        var options = authOptions.Value;

        if (string.IsNullOrWhiteSpace(options.PublicKeyPath))
            throw new InvalidOperationException("Security:Auth:PublicKeyPath no esta configurado.");

        var fullPublicKeyPath = ResolvePublicKeyPath(options.PublicKeyPath);
        if (string.IsNullOrEmpty(fullPublicKeyPath))
            throw new FileNotFoundException("No se encontró el archivo de Public Key.", options.PublicKeyPath);

        PublicKeyPem = File.ReadAllText(fullPublicKeyPath);
    }

    private static string? ResolvePublicKeyPath(string configuredPath)
    {
        if (Path.IsPathRooted(configuredPath) && File.Exists(configuredPath))
            return configuredPath;

        var probePaths = new[]
        {
            Path.Combine(AppContext.BaseDirectory, configuredPath),
            Path.Combine(Directory.GetCurrentDirectory(), configuredPath),
            configuredPath
        };

        foreach (var path in probePaths)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }
}
