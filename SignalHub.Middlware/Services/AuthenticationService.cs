using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using SignalHub.Middlware.Interfaces;
using SignalHub.Middlware.Options;
using System.Security.Claims;

namespace SignalHub.Middlware.Services
{
    public class HubexoAuthenticationService : IHubexoAuthenticationService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<HubexoAuthenticationService> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IOptions<HubexoAuthenticationOptions> _options;

        public HubexoAuthenticationService(IConfiguration configuration, 
            ILogger<HubexoAuthenticationService> logger,
            IHttpContextAccessor httpContextAccessor,
            IOptions<HubexoAuthenticationOptions> options)
        {
            _configuration = configuration;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
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

                await RevokeTokensAsync(context);

                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                
                await context.SignOutAsync("HubexoID", authProperties);

                _logger.LogInformation("Sign out completed successfully for user: {UserId}", userId);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during sign out process");
                return false;
            }
        }

        public async Task<bool> IsAuthenticatedAsync(HttpContext context)
        {
            var authResult = await context.AuthenticateAsync();
            return authResult.Succeeded && authResult.Principal?.Identity?.IsAuthenticated == true;
        }

        public async Task<ClaimsPrincipal?> GetCurrentUserAsync(HttpContext context)
        {
            var authResult = await context.AuthenticateAsync();
            return authResult.Succeeded ? authResult.Principal : null;
        }

        public string GetLogoutUrl(string? returnUrl = null)
        {
            var authority = _configuration["HubexoID:Authority"];
            var clientId = _configuration["HubexoID:ClientId"];
            var redirectUri = returnUrl ?? "/signout/complete";

            if (_httpContextAccessor.HttpContext != null)
            {
                var request = _httpContextAccessor.HttpContext.Request;
                if (redirectUri.StartsWith("/"))
                {
                    redirectUri = $"{request.Scheme}://{request.Host}{request.PathBase}{redirectUri}";
                }
            }

            return $"{authority}/logout?client_id={clientId}&post_logout_redirect_uri={Uri.EscapeDataString(redirectUri)}";
        }


        public async Task RevokeTokensAsync(HttpContext context)
        {
            try
            {
                var tokenResult = await context.GetTokenAsync("access_token");
                if (!string.IsNullOrEmpty(tokenResult))
                {
                    _logger.LogInformation("Revoking access token");
                }

                var refreshTokenResult = await context.GetTokenAsync("refresh_token");
                if (!string.IsNullOrEmpty(refreshTokenResult))
                {
                    _logger.LogInformation("Revoking refresh token");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error while attempting to revoke tokens");
            }
        }
    }
}