namespace SignalHub.Middlware.Components.Pages.Auth
{
    public partial class SignedOut
    {
        private void NavigateHome()
        {
            Navigation.NavigateTo("/", forceLoad: true);
        }

        private void SignInAgain()
        {
            Navigation.NavigateTo("/auth/login", forceLoad: true);
        }
    }
}
