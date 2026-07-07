using Security.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddCustomTokenAuth(builder.Configuration);
builder.Services.AddSecurityErrorReporting(builder.Configuration);

// 1. Configuración Nativa de OpenAPI .NET 9
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, cancellationToken) =>
    {
        var components = document.Components ??= new OpenApiComponents();

        components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();

        components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            In = ParameterLocation.Header,
            BearerFormat = "JWT",
            Description = "Introduce tu token JWT."
        };
        return Task.CompletedTask;
    });

    options.AddOperationTransformer((operation, context, cancellationToken) =>
    {
        var endpointMetadata = context.Description.ActionDescriptor.EndpointMetadata;
        if (endpointMetadata.Any(m => m is CustomAuthorizeAttribute))
        {
            operation.Security ??= new List<OpenApiSecurityRequirement>();
            var securityRequirement = new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecuritySchemeReference("Bearer", null),
                    new List<string>()
                }
            };
            operation.Security.Add(securityRequirement);
        }
        return Task.CompletedTask;
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi(); // <-- Si el paso 1 fue exitoso, esto ya no marcará error
    app.MapScalarApiReference(); 
}

app.UseSecurityErrorReporting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
