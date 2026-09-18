namespace Security.Auth;

/// <summary>
/// Lectura de la identidad Security.Auth de la petición actual.
/// No autentica peticiones ni concede permisos; usar después de la autenticación.
/// </summary>
public interface ISecurityIdentity
{
    /// <summary>Hay una única identidad autenticada del esquema Bearer de Security.Auth.</summary>
    bool IsAuthenticated { get; }

    /// <summary>Unknown si no hay identidad Security.Auth o typ no es user/system.</summary>
    SecurityIdentityType Type { get; }

    /// <summary>blikon_id para User; null si falta, es inválido, vacío o ambiguo.</summary>
    Guid? BlikonId { get; }

    /// <summary>system_id para System; null si falta, es inválido, vacío o ambiguo.</summary>
    Guid? SystemId { get; }
}
