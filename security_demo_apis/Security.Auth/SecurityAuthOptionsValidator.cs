using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace Security.Auth;

internal sealed partial class SecurityAuthOptionsValidator : IValidateOptions<SecurityAuthOptions>
{
    public ValidateOptionsResult Validate(string? name, SecurityAuthOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.SystemId))
            failures.Add("Security:Auth:SystemId no esta configurado.");
        else if (!Guid.TryParse(options.SystemId, out _))
            failures.Add("Security:Auth:SystemId debe ser un GUID valido.");

        if (string.IsNullOrWhiteSpace(options.ValidIssuer))
            failures.Add("Security:Auth:ValidIssuer no esta configurado.");

        if (string.IsNullOrWhiteSpace(options.ValidAudience))
            failures.Add("Security:Auth:ValidAudience no esta configurado.");

        var duplicateAliases = options.ScopeOwners.Keys
            .GroupBy(alias => alias, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key);

        foreach (var alias in duplicateAliases)
            failures.Add($"Security:Auth:ScopeOwners contiene el alias duplicado '{alias}'.");

        foreach (var (alias, systemId) in options.ScopeOwners)
        {
            if (!ScopeOwnerAliasRegex().IsMatch(alias))
                failures.Add($"El alias '{alias}' debe usar kebab-case en minusculas.");

            if (!Guid.TryParse(systemId, out _))
                failures.Add($"Security:Auth:ScopeOwners:{alias} debe contener un GUID valido.");

            if (!string.IsNullOrWhiteSpace(options.SystemId) &&
                systemId.Equals(options.SystemId, StringComparison.OrdinalIgnoreCase))
            {
                failures.Add($"El alias '{alias}' repite SystemId; usa el constructor corto de SecureAuth.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    [GeneratedRegex("^[a-z0-9]+(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex ScopeOwnerAliasRegex();
}
