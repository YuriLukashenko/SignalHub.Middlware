using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace SignalHub.Middlware.Middleware
{
    public class LogoutMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<LogoutMiddleware> _logger;
        private readonly string _remoteSignOutPath;
        private readonly string _signedOutCallbackPath;

        public LogoutMiddleware(RequestDelegate next, ILogger<LogoutMiddleware> logger, IConfiguration config)
        {
            _next = next;
            _logger = logger;
            _remoteSignOutPath = config["HubexoID:CallbackPath"] ?? "/signout-oidc-hubexo";
            _signedOutCallbackPath = config["HubexoID:SignedOutCallbackPath"] ?? "/signout-callback-oidc-hubexo";
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Path.StartsWithSegments(_remoteSignOutPath, StringComparison.OrdinalIgnoreCase))
            {
                await HandleRemoteSignOut(context);
                return;
            }

            if (context.Request.Path.StartsWithSegments(_signedOutCallbackPath, StringComparison.OrdinalIgnoreCase))
            {
                await HandleSignOutCallback(context);
                return;
            }

            await _next(context);
        }

        private async Task HandleRemoteSignOut(HttpContext context)
        {
            _logger.LogInformation("Handling remote sign out from HubexoID");
            
            var userId = context.User.FindFirst("sub")?.Value;
            _logger.LogInformation("Remote sign out for user: {UserId}", userId);
            
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            context.Response.StatusCode = 200;
            await context.Response.CompleteAsync();
        }

        private async Task HandleSignOutCallback(HttpContext context)
        {
            _logger.LogInformation("Handling sign out callback from HubexoID");
            
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            var returnUrl = context.Request.Query["state"].FirstOrDefault() ?? "/signout/complete";
            context.Response.Redirect(returnUrl);
            await context.Response.CompleteAsync();
        }
    }

    public static class LogoutMiddlewareExtensions
    {
        public static IApplicationBuilder UseLogoutMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<LogoutMiddleware>();
        }
    }
}