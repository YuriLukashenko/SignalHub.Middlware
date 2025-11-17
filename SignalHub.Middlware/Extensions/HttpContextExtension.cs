using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace SignalHub.Middlware.Extensions
{
    public static class HttpContextExtensions
    {
        public static async Task<bool> IsAuthenticatedAsync(this HttpContext context)
        {
            var authResult = await context.AuthenticateAsync();
            return authResult.Succeeded && authResult.Principal?.Identity?.IsAuthenticated == true;
        }

        public static async Task<ClaimsPrincipal?> GetUserAsync(this HttpContext context)
        {
            var authResult = await context.AuthenticateAsync();
            return authResult.Succeeded ? authResult.Principal : null;
        }

        public static string? GetUserId(this HttpContext context)
        {
            return context.User?.FindFirst("sub")?.Value
                ?? context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        }

        public static string? GetUserEmail(this HttpContext context)
        {
            return context.User?.FindFirst("email")?.Value
                ?? context.User?.FindFirst(ClaimTypes.Email)?.Value;
        }

        public static string? GetUserName(this HttpContext context)
        {
            return context.User?.FindFirst("name")?.Value
                ?? context.User?.FindFirst("given_name")?.Value
                ?? context.User?.FindFirst(ClaimTypes.Name)?.Value
                ?? context.User?.Identity?.Name;
        }

        public static async Task<string?> GetAccessTokenAsync(this HttpContext context)
        {
            return await context.GetTokenAsync("access_token");
        }

        public static async Task<string?> GetRefreshTokenAsync(this HttpContext context)
        {
            return await context.GetTokenAsync("refresh_token");
        }

        public static async Task<string?> GetIdTokenAsync(this HttpContext context)
        {
            return await context.GetTokenAsync("id_token");
        }

        public static async Task<Dictionary<string, string>> GetAllTokensAsync(this HttpContext context)
        {
            var tokens = new Dictionary<string, string>();
            
            var accessToken = await context.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(accessToken))
                tokens["access_token"] = accessToken;

            var refreshToken = await context.GetTokenAsync("refresh_token");
            if (!string.IsNullOrEmpty(refreshToken))
                tokens["refresh_token"] = refreshToken;

            var idToken = await context.GetTokenAsync("id_token");
            if (!string.IsNullOrEmpty(idToken))
                tokens["id_token"] = idToken;

            return tokens;
        }

        public static async Task<bool> SignOutCompletelyAsync(
            this HttpContext context,
            string? returnUrl = null)
        {
            try
            {
                var authProperties = new AuthenticationProperties
                {
                    RedirectUri = returnUrl ?? "/"
                };

                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                
                await context.SignOutAsync("HubexoID", authProperties);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool HasRole(this HttpContext context, string role)
        {
            return context.User?.IsInRole(role) == true;
        }

        public static IEnumerable<string> GetUserRoles(this HttpContext context)
        {
            return context.User?.Claims
                .Where(c => c.Type == "role" || c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                ?? Enumerable.Empty<string>();
        }

        public static Dictionary<string, string> GetAllClaims(this HttpContext context)
        {
            var claims = new Dictionary<string, string>();
            
            if (context.User?.Claims != null)
            {
                foreach (var claim in context.User.Claims)
                {
                    if (!claims.ContainsKey(claim.Type))
                    {
                        claims[claim.Type] = claim.Value;
                    }
                    else
                    {
                        claims[claim.Type] += $", {claim.Value}";
                    }
                }
            }

            return claims;
        }

        public static async Task<DateTime?> GetTokenExpirationAsync(this HttpContext context)
        {
            var expiresAt = await context.GetTokenAsync("expires_at");
            
            if (!string.IsNullOrEmpty(expiresAt) && 
                DateTimeOffset.TryParse(expiresAt, out var expiration))
            {
                return expiration.UtcDateTime;
            }

            return null;
        }

        public static async Task<bool> IsTokenExpiredAsync(this HttpContext context)
        {
            var expiration = await context.GetTokenExpirationAsync();
            return expiration.HasValue && expiration.Value <= DateTime.UtcNow;
        }

        public static void SetAuthCookie(
            this HttpContext context,
            string name,
            string value,
            int? expireDays = null)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = expireDays.HasValue 
                    ? DateTimeOffset.UtcNow.AddDays(expireDays.Value)
                    : DateTimeOffset.UtcNow.AddHours(1)
            };

            context.Response.Cookies.Append(name, value, cookieOptions);
        }

        public static void RemoveAuthCookie(this HttpContext context, string name)
        {
            context.Response.Cookies.Delete(name);
        }

        public static bool IsAjaxRequest(this HttpContext context)
        {
            return context.Request.Headers["X-Requested-With"] == "XMLHttpRequest";
        }

        public static bool IsApiRequest(this HttpContext context)
        {
            return context.Request.Path.StartsWithSegments("/api");
        }

        public static string GetBaseUrl(this HttpContext context)
        {
            var request = context.Request;
            return $"{request.Scheme}://{request.Host}{request.PathBase}";
        }

        public static string GetFullUrl(this HttpContext context)
        {
            var request = context.Request;
            return $"{request.Scheme}://{request.Host}{request.PathBase}{request.Path}{request.QueryString}";
        }
    }
}