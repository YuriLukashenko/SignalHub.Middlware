using System.Security.Claims;

namespace SignalHub.Middlware.Interfaces
{
    public interface IHubexoAuthenticationService
    {
        Task<bool> SignOutAsync(HttpContext context, string? returnUrl = null);
    }
}
