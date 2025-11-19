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
    }
}
