using ClientDemo.Models;
using ClientDemo.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace ClientDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CountriesController : ControllerBase
{
    private readonly IProtectedApiClient _protectedApiClient;
    private readonly ILogger<CountriesController> _logger;

    public CountriesController(IProtectedApiClient protectedApiClient, ILogger<CountriesController> logger)
    {
        _protectedApiClient = protectedApiClient;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<List<Country>>> GetCountries()
    {
        try
        {
            _logger.LogInformation("Fetching countries...");
            var countries = await _protectedApiClient.GetAsync<List<Country>>("api/Countries")
                ?? new List<Country>();
            
            if (countries == null || countries.Count == 0)
            {
                _logger.LogWarning("No countries found");
                return Ok(new List<Country>());
            }

            _logger.LogInformation($"Successfully retrieved {countries.Count} countries");
            return Ok(countries);
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error fetching countries: {ex.Message}");
            return StatusCode(StatusCodes.Status500InternalServerError, 
                new { error = "An error occurred while fetching countries", details = ex.Message });
        }
    }

    [HttpGet("test")]
    public async Task<ActionResult<JsonElement>> TestEndpoint(CancellationToken cancellationToken)
    {
        var request = new
        {
            numeroTelefono = "2225498881",
            plataforma = "web"
        };

        _logger.LogInformation("Sending verification code test request...");

        var response = await _protectedApiClient.PostAsync<object, JsonElement>(
            "/api/authentication/send-verification-code",
            request,
            cancellationToken);

        return Ok(response);
    }

    [HttpPost]
    public async Task<ActionResult<Country>> CreateCountry(Country country, CancellationToken cancellationToken)
    {
        var created = await _protectedApiClient.PostAsync<Country, Country>(
            "api/Countries", country, cancellationToken);
        return Ok(created);
    }
}
