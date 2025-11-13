using System.Collections.Generic;

namespace SignalHub.Middlware.Models
{
    public class HubexoAuthenticationOptions
    {
        public string Authority { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string? CognitoAppClientId { get; set; }

        public string? MetadataAddress { get; set; }
        public string ResponseType { get; set; } = "code";

        public List<string> Scopes { get; set; } = new List<string>
        {
            "openid",
            "profile",
            "email"
        };

        public string CallbackPath { get; set; } = "/signin-oidc-hubexo";
        public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc-hubexo";
        public bool SaveTokens { get; set; } = true;
        public bool RequestOfflineAccess { get; set; } = true;
        public string NameClaimType { get; set; } = "name";
        public string SchemeName { get; set; } = "HubexoID";

        public void Validate()
        {
            if (string.IsNullOrEmpty(Authority))
                throw new ArgumentException("Authority is required", nameof(Authority));

            if (string.IsNullOrEmpty(ClientId))
                throw new ArgumentException("ClientId is required", nameof(ClientId));

            if (string.IsNullOrEmpty(ClientSecret))
                throw new ArgumentException("ClientSecret is required", nameof(ClientSecret));

            if (string.IsNullOrEmpty(MetadataAddress))
            {
                MetadataAddress = $"{Authority.TrimEnd('/')}/.well-known/openid-configuration";
            }
        }
    }

    public class HubexoApiAuthenticationOptions
    {
        public string Authority { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
        public string? MetadataAddress { get; set; }
        public bool RequireHttpsMetadata { get; set; } = true;

        public bool ValidateIssuer { get; set; } = true;
        public bool ValidateAudience { get; set; } = true;
        public bool ValidateLifetime { get; set; } = true;
        public bool ValidateIssuerSigningKey { get; set; } = true;
        public string SchemeName { get; set; } = "HubexoBearer";

        public void Validate()
        {
            if (string.IsNullOrEmpty(Authority))
                throw new ArgumentException("Authority is required", nameof(Authority));

            if (string.IsNullOrEmpty(Audience))
                throw new ArgumentException("Audience is required", nameof(Audience));

            if (string.IsNullOrEmpty(MetadataAddress))
            {
                MetadataAddress = $"{Authority.TrimEnd('/')}/.well-known/openid-configuration";
            }
        }
    }
}
