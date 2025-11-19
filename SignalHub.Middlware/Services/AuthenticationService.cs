using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using SignalHub.Middlware.Interfaces;
using SignalHub.Middlware.Options;

namespace SignalHub.Middlware.Services
{
    public class HubexoAuthenticationService : IHubexoAuthenticationService
    {
        private readonly ILogger<HubexoAuthenticationService> _logger;
        private readonly IOptions<HubexoAuthenticationOptions> _options;

        public HubexoAuthenticationService(ILogger<HubexoAuthenticationService> logger, IOptions<HubexoAuthenticationOptions> options)
        {
            _logger = logger;
            _options = options;
        }

        public async Task<bool> SignOutAsync(HttpContext context, string? returnUrl = null)
        {
            try
            {
                var userId = context.User.FindFirst("sub")?.Value;
                var userEmail = context.User.FindFirst("email")?.Value;

                _logger.LogInformation($"Starting sign out process for user: {userId} ({userEmail})");

                var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
                var redirectUrl = string.IsNullOrEmpty(returnUrl)
                    ? $"{baseUrl}{_options.Value.SignedOutRedirectUri}"
                    : returnUrl;

                var authProperties = new AuthenticationProperties
                {
                    RedirectUri = redirectUrl
                };

                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                
                await context.SignOutAsync(_options.Value.SchemeName, authProperties);

                _logger.LogInformation($"Sign out completed successfully for user: {userId}");
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during sign out process");
                return false;
            }
        }
    }
}