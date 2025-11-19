namespace SignalHub.Middlware.Options
{
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
