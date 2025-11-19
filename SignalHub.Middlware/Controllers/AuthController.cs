using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using SignalHub.Middlware.Interfaces;

namespace SignalHub.Middlware.Controllers
{
    [Route("[controller]")]
    public class AuthController : Controller
    {
        private readonly ILogger<AuthController> _logger;
        private readonly IHubexoAuthenticationService _hubexoAuthenticationService;

        public AuthController(ILogger<AuthController> logger, IHubexoAuthenticationService hubexoAuthenticationService)
        {
            _logger = logger;
            _hubexoAuthenticationService = hubexoAuthenticationService;
        }

        [HttpGet("login")]
        public IActionResult Login(string? returnUrl = null)
        {
            var redirectUrl = string.IsNullOrEmpty(returnUrl) ? "/" : returnUrl;

            var authenticationProperties = new AuthenticationProperties
            {
                RedirectUri = redirectUrl
            };

            return Challenge(authenticationProperties, "HubexoID");
        }

        [HttpGet("signout")]
        public async Task<IActionResult> SignOut(string? returnUrl = null)
        {
            if (await _hubexoAuthenticationService.SignOutAsync(HttpContext, returnUrl))
            {
                return new EmptyResult();
            }

            return StatusCode(500, "Error during sign out process");
        }
    }
}