using Microsoft.AspNetCore.Mvc;
using DemoAPIWithSecurity.Models;
using Security.Auth;

namespace DemoAPIWithSecurity.Controllers;

/// <summary>
/// Controlador para gestionar información de países
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
    /// Obtiene la lista completa de países
    /// </summary>
    /// <remarks>
    /// Ejemplo de solicitud:
    /// 
    ///     GET /api/countries
    /// </remarks>
    /// <returns>Lista de todos los países disponibles</returns>
    /// <response code="200">Retorna la lista de países</response>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [CustomAuthorize("catalogopaises.read")] // Requiere el permiso "countries:read" para acceder a esta acción
    public ActionResult<IEnumerable<Country>> GetCountries()
    {
        return Ok(Countries);
    }

    [HttpGet("demo-error")]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public IActionResult DemoError()
    {
        throw new InvalidOperationException("Error de prueba para SecurityErrorReportingMiddleware.");
    }

    /// <summary>
    /// Obtiene un país específico por su ID
    /// </summary>
    /// <remarks>
    /// Ejemplo de solicitud:
    /// 
    ///     GET /api/countries/1
    /// </remarks>
    /// <param name="id">ID del país a consultar</param>
    /// <returns>País encontrado</returns>
    /// <response code="200">Retorna el país solicitado</response>
    /// <response code="404">Si el país no existe</response>
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
