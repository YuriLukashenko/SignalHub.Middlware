using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace SignalHub.Middlware.Controllers
{
    [Route("[controller]")]
    public class AuthController : Controller
    {
        private readonly ILogger<AuthController> _logger;

        public AuthController(ILogger<AuthController> logger)
        {
            _logger = logger;
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
        [HttpPost("signout")]
        public async Task<IActionResult> Logout(string? returnUrl = null)
        {
            var userId = User.FindFirst("sub")?.Value;
            _logger.LogInformation("User {UserId} is logging out", userId);

            var redirectUrl = string.IsNullOrEmpty(returnUrl)
                ? "https://localhost:44347/signout/complete"
                : returnUrl;

            var authenticationProperties = new AuthenticationProperties
            {
                RedirectUri = redirectUrl
            };

            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            await HttpContext.SignOutAsync("HubexoID", authenticationProperties);

            return new EmptyResult();
        }

        [HttpGet("access-denied")]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}