using Microsoft.Extensions.Options;

namespace DemoAPIWithSecurity.Auth;

public sealed class PublicKeyProvider
{
    public string PublicKeyPem { get; }

    public PublicKeyProvider(IOptions<AuthOptions> authOptions)
    {
        var options = authOptions.Value;

        if (string.IsNullOrWhiteSpace(options.PublicKeyPath))
            throw new InvalidOperationException("AuthSettings:PublicKeyPath no está configurado.");

        var fullPublicKeyPath = Path.Combine(AppContext.BaseDirectory, options.PublicKeyPath);
        if (!File.Exists(fullPublicKeyPath))
            throw new FileNotFoundException("No se encontró el archivo de Public Key.", fullPublicKeyPath);

        PublicKeyPem = File.ReadAllText(fullPublicKeyPath);
    }
}
