using DemoAPIWithSecurity.Models;
using Microsoft.AspNetCore.Mvc;
using Security.Auth;

namespace DemoAPIWithSecurity.Controllers;

[ApiController]
[Route("api/authorization-examples")]
[Produces("application/json")]
public sealed class AuthorizationExamplesController : ControllerBase
{
    /// <summary>
    /// Demuestra que los claims validados estan disponibles en HttpContext.User.
    /// </summary>
    [HttpGet("current-user")]
    [SecureAuth("system", "catalogopaises.read")]
    public IActionResult GetCurrentUser()
    {
        return Ok(new
        {
            blikonId = User.FindFirst("blikon_id")?.Value
        });
    }

    /// <summary>
    /// Valida un scope externo usando el accountId de la ruta.
    /// </summary>
    [HttpGet("developer-accounts/{accountId}")]
    [SecureAuth(
        "developer-system",
        "dev-account.{accountId}",
        "develop.write,account.changename")]
    public IActionResult GetDeveloperAccount(string accountId)
    {
        return Ok(new { accountId, source = "route" });
    }

    /// <summary>
    /// Valida un scope externo usando el accountId del body JSON.
    /// </summary>
    [HttpPost("developer-accounts")]
    [SecureAuth(
        "developer-system",
        "dev-account.{accountId}",
        "develop.write")]
    public IActionResult UpdateDeveloperAccount([FromBody] UpdateDeveloperAccountRequest request)
    {
        return Ok(new { request.AccountId, source = "body" });
    }
}
