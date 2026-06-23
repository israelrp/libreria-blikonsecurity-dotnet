using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace DemoAPIWithSecurity.Auth;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCustomTokenAuth(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();
        services.AddHttpClient();
        services.Configure<AuthOptions>(configuration.GetSection(AuthOptions.SectionName));

        services.AddSingleton<PublicKeyProvider>();

        services.AddAuthentication("Bearer")
            .AddScheme<AuthenticationSchemeOptions, NoOpAuthHandler>("Bearer", _ => { });

        services.AddScoped<IAuthorizationHandler, TokenAuthorizationHandler>();
        services.AddAuthorization();

        return services;
    }
}
