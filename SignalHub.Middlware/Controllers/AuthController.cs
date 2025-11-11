using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace SignalHub.Middlware.Controllers
{
    [Route("[controller]")]
    public class AuthController : Controller
    {
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

        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                "HubexoID"
            );
        }

        [HttpGet("access-denied")]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
