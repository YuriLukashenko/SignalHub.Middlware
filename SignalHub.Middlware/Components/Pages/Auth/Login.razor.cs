using System.Security.Claims;
using Microsoft.AspNetCore.Components;

namespace SignalHub.Middlware.Components.Pages.Auth
{
    public partial class Login
    {
        [SupplyParameterFromQuery(Name = "returnUrl")]
        public string? ReturnUrl { get; set; }

        private void LoginWithHubexoID()
        {
            var returnUrl = ReturnUrl ?? "/";
            Navigation.NavigateTo($"/auth/login?returnUrl={Uri.EscapeDataString(returnUrl)}", forceLoad: true);
        }

        protected override async Task OnInitializedAsync()
        {
            var authState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
            if (authState.User.Identity?.IsAuthenticated == true && string.IsNullOrEmpty(ReturnUrl))
            {
                Navigation.NavigateTo("/");
            }
        }
    }
}
