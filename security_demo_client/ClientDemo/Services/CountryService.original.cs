#if false
// Implementacion original conservada temporalmente para pruebas y comparacion.
// No se compila. El codigo activo se encuentra en BlikonSecurityClient,
// BlikonTokenProvider y ProtectedApiClient.

using ClientDemo.Models;

namespace ClientDemo.Services
{
    public interface ICountryService
    {
        Task<List<Country>> GetCountriesAsync();
    }

    public class CountryService : ICountryService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<CountryService> _logger;

        private readonly string BaseUrlBlikonSecurity = "https://security-api.dev.com.pro/api/v1";
        private const string LoginAPI = "/auth/systems";
        private const string TokenAlcanceAPI = "/tokens";
        private const string CountriesUrl = "http://localhost:5165/api/Countries";
        private const string SystemId = "dd478741-55df-49be-9887-7ab4d81f01e1";
        private const string Secret = "2vT5QSM3zYc8";
        private const string SystemAPIId = "fa5492fe-7f66-4ceb-b2a6-adeafc0ff93d";

        public CountryService(HttpClient httpClient, ILogger<CountryService> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<List<Country>> GetCountriesAsync()
        {
            try
            {
                var options = new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                // Paso 1: autenticar el aplicativo en Blikon Security.
                var authRequest = new AuthRequest
                {
                    ClientSystemId = SystemId,
                    ClientSecret = Secret
                };
                var authContent = new StringContent(
                    System.Text.Json.JsonSerializer.Serialize(authRequest),
                    System.Text.Encoding.UTF8,
                    "application/json");

                var authResponse = await _httpClient.PostAsync(BaseUrlBlikonSecurity + LoginAPI, authContent);
                authResponse.EnsureSuccessStatusCode();

                var authResponseBody = await authResponse.Content.ReadAsStringAsync();
                var authData = System.Text.Json.JsonSerializer.Deserialize<AuthResponse>(authResponseBody, options);

                if (!authData?.Result ?? false)
                {
                    throw new Exception($"Authentication failed: {authData?.Message}");
                }

                if (authData == null || string.IsNullOrEmpty(authData.AccessToken))
                {
                    throw new Exception("No access token received from authentication");
                }

                // Paso 2: solicitar el token de alcance para la API destino.
                var tokenAlcanceBody = new
                {
                    requestedSystems = new Dictionary<string, string[]>
                    {
                        { SystemAPIId, Array.Empty<string>() }
                    }
                };
                var tokenAlcanceRequestJSON = new StringContent(
                    System.Text.Json.JsonSerializer.Serialize(tokenAlcanceBody),
                    System.Text.Encoding.UTF8,
                    "application/json");

                var tokenAlcanceRequest = new HttpRequestMessage(
                    HttpMethod.Post,
                    BaseUrlBlikonSecurity + TokenAlcanceAPI);
                tokenAlcanceRequest.Headers.Add("Authorization", $"Bearer {authData.AccessToken}");
                tokenAlcanceRequest.Content = tokenAlcanceRequestJSON;

                var tokenAlcanceResponse = await _httpClient.SendAsync(tokenAlcanceRequest);
                tokenAlcanceResponse.EnsureSuccessStatusCode();

                var tokenAlcanceResponseBody = await tokenAlcanceResponse.Content.ReadAsStringAsync();
                var tokenAlcanceData = System.Text.Json.JsonSerializer.Deserialize<AuthResponse>(
                    tokenAlcanceResponseBody,
                    options);

                if (!tokenAlcanceData?.Result ?? false)
                {
                    throw new Exception($"Authentication failed: {tokenAlcanceData?.Message}");
                }

                if (tokenAlcanceData == null || string.IsNullOrEmpty(tokenAlcanceData.AccessToken))
                {
                    throw new Exception("No access token received from authentication");
                }

                // Paso 3: consumir la API protegida con el token de alcance.
                // var countriesRequest = new HttpRequestMessage(HttpMethod.Get, CountriesUrl);
                var countriesRequest = new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://localhost:44318/api/Usuarios/EnviarCodigoAutenticacion");
                countriesRequest.Headers.Add(
                    "Authorization",
                    $"Bearer {tokenAlcanceData.AccessToken}");

                var countriesResponse = await _httpClient.SendAsync(countriesRequest);
                var countriesBody = await countriesResponse.Content.ReadAsStringAsync();
                countriesResponse.EnsureSuccessStatusCode();

                var countries = System.Text.Json.JsonSerializer.Deserialize<List<Country>>(
                    countriesBody,
                    options);

                return countries ?? new List<Country>();
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError($"HTTP request error: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error: {ex.Message}");
                throw;
            }
        }
    }
}
#endif
