using Microsoft.AspNetCore.Mvc;
using DemoAPIWithSecurity.Models;
using Security.Auth;

namespace DemoAPIWithSecurity.Controllers;

/// <summary>
/// Controlador para gestionar información de países.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class CountriesController : ControllerBase
{
    private static readonly Country[] Countries = new[]
    {
        new Country(1, "México", "MX"),
        new Country(2, "Estados Unidos", "US"),
        new Country(3, "Canadá", "CA"),
        new Country(4, "Brasil", "BR"),
        new Country(5, "Argentina", "AR"),
        new Country(6, "Chile", "CL"),
        new Country(7, "Colombia", "CO"),
        new Country(8, "España", "ES"),
        new Country(9, "Francia", "FR"),
        new Country(10, "Alemania", "DE")
    };

    /// <summary>
    /// Obtiene la lista completa de países con permiso de sistema.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [SecureAuth("system", "catalogopaises.read")]
    public ActionResult<IEnumerable<Country>> GetCountries()
    {
        return Ok(Countries);
    }

    /// <summary>
    /// Obtiene países para un place usando un token de usuario.
    /// </summary>
    [HttpGet("place/{spaceId}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [SecureAuth("place.{spaceId}", "catalogopaises.read")]
    public ActionResult<IEnumerable<Country>> GetCountriesByPlace(int spaceId)
    {
        return Ok(new { spaceId, countries = Countries });
    }

    /// <summary>
    /// Genera un error de prueba para el middleware de reporte.
    /// </summary>
    [HttpGet("demo-error")]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public IActionResult DemoError()
    {
        throw new InvalidOperationException("Error de prueba para SecurityErrorReportingMiddleware.");
    }

    /// <summary>
    /// Obtiene un país específico por su ID.
    /// </summary>
    [HttpGet("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public ActionResult<Country> GetCountryById(int id)
    {
        var country = Countries.FirstOrDefault(c => c.Id == id);
        if (country == null)
        {
            return NotFound();
        }

        return Ok(country);
    }
}
