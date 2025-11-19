using System.Security.Claims;

namespace SignalHub.Middlware.Interfaces
{
    public interface IHubexoAuthenticationService
    {
        Task<bool> SignOutAsync(HttpContext context, string? returnUrl = null);
        Task<bool> IsAuthenticatedAsync(HttpContext context);
        Task<ClaimsPrincipal?> GetCurrentUserAsync(HttpContext context);
        string GetLogoutUrl(string? returnUrl = null);
        Task RevokeTokensAsync(HttpContext context);
    }
}
