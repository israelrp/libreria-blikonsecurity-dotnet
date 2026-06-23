using ClientDemo.Options;
using ClientDemo.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddOpenApi();
builder.Services.AddControllersWithViews();
builder.Services.AddOptions<BlikonSecurityOptions>()
    .Bind(builder.Configuration.GetSection(BlikonSecurityOptions.SectionName))
    .Validate(o => Uri.TryCreate(o.SecurityBaseUrl, UriKind.Absolute, out _), "SecurityBaseUrl must be an absolute URL.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.LoginEndpoint), "LoginEndpoint is required.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.TokenEndpoint), "TokenEndpoint is required.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.ClientSystemId), "ClientSystemId is required.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.ClientSecret), "ClientSecret is required.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.TargetSystemId), "TargetSystemId is required.")
    .ValidateOnStart();

builder.Services.AddOptions<ProtectedApiOptions>()
    .Bind(builder.Configuration.GetSection(ProtectedApiOptions.SectionName))
    .Validate(o => Uri.TryCreate(o.BaseUrl, UriKind.Absolute, out _), "ProtectedApi:BaseUrl must be an absolute URL.")
    .ValidateOnStart();

builder.Services.AddHttpClient(BlikonSecurityClient.HttpClientName, (services, client) =>
{
    var options = services.GetRequiredService<Microsoft.Extensions.Options.IOptions<BlikonSecurityOptions>>().Value;
    client.BaseAddress = new Uri(options.SecurityBaseUrl.TrimEnd('/') + "/");
});

builder.Services.AddSingleton<IBlikonSecurityClient, BlikonSecurityClient>();
builder.Services.AddSingleton<IBlikonTokenProvider, BlikonTokenProvider>();
builder.Services.AddHttpClient<IProtectedApiClient, ProtectedApiClient>((services, client) =>
{
    var options = services.GetRequiredService<Microsoft.Extensions.Options.IOptions<ProtectedApiOptions>>().Value;
    client.BaseAddress = new Uri(options.BaseUrl.TrimEnd('/') + "/");
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapControllers();

app.Run();
