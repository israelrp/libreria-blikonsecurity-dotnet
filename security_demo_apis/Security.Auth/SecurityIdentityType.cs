namespace Security.Auth;

/// <summary>Tipo de identidad declarado en el claim typ del token autenticado.</summary>
public enum SecurityIdentityType
{
    Unknown = 0,
    User = 1,
    System = 2
}
