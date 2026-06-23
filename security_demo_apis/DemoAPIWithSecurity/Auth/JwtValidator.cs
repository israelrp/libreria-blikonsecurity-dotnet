using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

namespace DemoAPIWithSecurity.Auth
{
    public class JwtValidator
    {
        public static async Task<JwtValidationResult> ValidarTokenAsync(
            string token,
            string publicKeyPem,
            string validIssuer,
            string validAudience)
        {
            var response = new JwtValidationResult();

            try
            {
                // 1. Importar la clave pública RSA desde el string PEM
                using var rsa = RSA.Create();
                rsa.ImportFromPem(publicKeyPem.ToCharArray());

                // 2. Crear la clave de seguridad desde parámetros (evita usar una instancia RSA desechable en validación)
                var rsaParameters = rsa.ExportParameters(false);
                var securityKey = new RsaSecurityKey(rsaParameters);

                // 3. Configurar los parámetros de validación
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey,
                    TryAllIssuerSigningKeys = true,
                    IssuerSigningKeyResolver = (_, _, _, _) => new[] { securityKey },
                    ValidateIssuer = true,
                    ValidIssuer = validIssuer,
                    ValidateAudience = true,
                    ValidAudience = validAudience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                // 4. Usar JsonWebTokenHandler para validar y decodificar
                var handler = new JsonWebTokenHandler();
                var result = await handler.ValidateTokenAsync(token, validationParameters);

                if (result.IsValid)
                {
                    response.IsValid = true;

                    // Obtener el token decodificado para extraer sus Claims
                    if (result.SecurityToken is JsonWebToken jwt)
                    {
                        foreach (var claim in jwt.Claims)
                        {
                            // Si un claim se repite (ej. múltiples roles), concatenamos sus valores por coma
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
            // Guardamos los claims como llave-valor para que sea fácil acceder a ellos
            public Dictionary<string, string> Claims { get; set; } = new();
        }
    }
}