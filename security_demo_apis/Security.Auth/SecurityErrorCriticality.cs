using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace Security.Auth;

internal static class SecurityErrorCriticality
{
    public const string Critical = "critical";
    public const string High = "high";
    public const string Medium = "medium";
    public const string Low = "low";

    private static readonly HashSet<string> AllowedValues = new(StringComparer.OrdinalIgnoreCase)
    {
        Critical,
        High,
        Medium,
        Low
    };

    public static string Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return Critical;

        var normalized = value.Trim().ToLowerInvariant();
        if (!AllowedValues.Contains(normalized))
            throw new ArgumentException($"Criticality debe ser uno de: {string.Join(", ", AllowedValues)}.");

        return normalized;
    }

    public static string FromException(Exception exception, int statusCode)
    {
        if (exception is TimeoutException or HttpRequestException)
            return High;

        return FromStatusCode(statusCode);
    }

    public static string FromStatusCode(int statusCode)
    {
        return statusCode switch
        {
            >= StatusCodes.Status500InternalServerError => Critical,
            StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden => Medium,
            >= StatusCodes.Status400BadRequest => Low,
            _ => Low
        };
    }
}
