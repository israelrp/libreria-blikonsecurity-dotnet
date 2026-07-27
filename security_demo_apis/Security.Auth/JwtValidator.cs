using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Security.Auth;

public class JwtValidator
{
    public static JwtValidationResult FromPrincipal(ClaimsPrincipal principal)
    {
        var response = new JwtValidationResult
        {
            IsValid = principal.Identity?.IsAuthenticated == true,
            Principal = principal,
            Audiences = principal.Claims
                .Where(claim => claim.Type == "aud")
                .Select(claim => claim.Value)
                .Where(audience => !string.IsNullOrWhiteSpace(audience))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray()
        };

        foreach (var claim in principal.Claims)
        {
            if (response.Claims.ContainsKey(claim.Type))
                response.Claims[claim.Type] += $",{claim.Value}";
            else
                response.Claims[claim.Type] = claim.Value;
        }

        return response;
    }

    public static async Task<JwtValidationResult> ValidarTokenAsync(
        string token,
        string publicKeyPem,
        string validIssuer,
        string validAudience)
    {
        return await ValidarTokenAsync(token, publicKeyPem, validIssuer, new[] { validAudience });
    }

    public static async Task<JwtValidationResult> ValidarTokenAsync(
        string token,
        string publicKeyPem,
        string validIssuer,
        IEnumerable<string> validAudiences)
    {
        var response = new JwtValidationResult();

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem.ToCharArray());

            var rsaParameters = rsa.ExportParameters(false);
            var securityKey = new RsaSecurityKey(rsaParameters);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey,
                TryAllIssuerSigningKeys = true,
                IssuerSigningKeyResolver = (_, _, _, _) => new[] { securityKey },
                ValidateIssuer = true,
                ValidIssuer = validIssuer,
                ValidateAudience = true,
                ValidAudiences = validAudiences,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var handler = new JsonWebTokenHandler();
            var result = await handler.ValidateTokenAsync(token, validationParameters);

            if (result.IsValid)
            {
                response.IsValid = true;

                if (result.SecurityToken is JsonWebToken jwt)
                {
                    var identity = new ClaimsIdentity(
                        jwt.Claims,
                        SecurityAuthDefaults.AuthenticationScheme);
                    response.Principal = new ClaimsPrincipal(identity);
                    response.Audiences = jwt.Audiences
                        .Where(audience => !string.IsNullOrWhiteSpace(audience))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();

                    foreach (var claim in jwt.Claims)
                    {
                        if (response.Claims.ContainsKey(claim.Type))
                        {
                            response.Claims[claim.Type] += $",{claim.Value}";
                        }
                        else
                        {
                            response.Claims[claim.Type] = claim.Value;
                        }
                    }
                }
            }
            else
            {
                response.IsValid = false;
                response.ErrorMessage = result.Exception?.Message ?? "Token inválido.";
            }
        }
        catch (Exception ex)
        {
            response.IsValid = false;
            response.ErrorMessage = ex.Message;
        }

        return response;
    }

    public class JwtValidationResult
    {
        public bool IsValid { get; set; }
        public string? ErrorMessage { get; set; }
        public ClaimsPrincipal? Principal { get; set; }
        public Dictionary<string, string> Claims { get; set; } = new();
        public IReadOnlyCollection<string> Audiences { get; set; } = Array.Empty<string>();
    }
}
