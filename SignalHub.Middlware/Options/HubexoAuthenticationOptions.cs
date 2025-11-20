namespace SignalHub.Middlware.Options
{
    public class HubexoAuthenticationOptions
    {
        public string Authority { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string? CognitoAppClientId { get; set; }
        public string? MetadataAddress { get; set; }
        public string ResponseType { get; set; } = "code";
        public IEnumerable<string> Scopes { get; set; } = new List<string> { "openid", "profile", "email" };
        public string CallbackPath { get; set; } = "/auth/login";
        public string RemoteSignOutPath { get; set; } = "/signout-oidc-hubexo";
        public string SignedOutCallbackPath { get; set; } = "/signout/callback";
        public string SignedOutRedirectUri { get; set; } = "/signout/complete";
        public IEnumerable<string> PostLogoutRedirectUris { get; set; } = new List<string>();
        public string SchemeName { get; set; } = "HubexoID";
        public bool RequirePkce { get; set; } = true;
        public bool SaveTokens { get; set; } = true;
        public bool RequestOfflineAccess { get; set; } = true;
        public bool GetClaimsFromUserInfoEndpoint { get; set; }
        public string NameClaimType { get; set; } = "name";
        public string ResponseMode { get; set; } = "query";
    }
}
