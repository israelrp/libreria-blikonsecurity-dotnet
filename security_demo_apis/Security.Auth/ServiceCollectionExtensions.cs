using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Security.Auth;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCustomTokenAuth(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();
        services.AddHttpClient();
        services.Configure<SecurityAuthOptions>(configuration.GetSection(SecurityAuthOptions.SectionName));

        services.AddSingleton<PublicKeyProvider>();

        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";
                options.DefaultForbidScheme = "Bearer";
            })
            .AddScheme<AuthenticationSchemeOptions, NoOpAuthHandler>("Bearer", _ => { });

        services.AddScoped<IAuthorizationHandler, TokenAuthorizationHandler>();
        services.AddAuthorization();

        return services;
    }

    public static IServiceCollection AddSecurityErrorReporting(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();
        services.Configure<SecurityAuthOptions>(configuration.GetSection(SecurityAuthOptions.SectionName));
        services.Configure<SecurityErrorOptions>(configuration.GetSection(SecurityErrorOptions.SectionName));

        services.AddHttpClient(SecurityHttpClientNames.ErrorReporting, (serviceProvider, client) =>
        {
            var options = serviceProvider.GetRequiredService<IOptions<SecurityErrorOptions>>().Value;
            if (string.IsNullOrWhiteSpace(options.BaseUrl))
                throw new InvalidOperationException("Security:Errors:BaseUrl no esta configurado.");

            client.BaseAddress = new Uri(options.BaseUrl.TrimEnd('/') + "/");
        });

        services.AddSingleton<ISecuritySystemTokenProvider, SecuritySystemTokenProvider>();
        services.AddSingleton<ISecurityErrorReporter, SecurityErrorReporter>();

        return services;
    }

    public static IApplicationBuilder UseSecurityErrorReporting(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SecurityErrorReportingMiddleware>();
    }
}
