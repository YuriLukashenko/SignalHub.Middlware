using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SignalHub.Middlware.Authentication;
using SignalHub.Middlware.Options;

namespace SignalHub.Middlware.Extensions
{
    public static class AuthenticationExtensions
    {
        public static IServiceCollection AddHubexoAuthentication(this IServiceCollection services,
            IConfiguration config)
        {
            var oidc = config.GetSection("HubexoID").Get<HubexoAuthenticationOptions>()!;
            var api = config.GetSection("HubexoAPI").Get<HubexoApiAuthenticationOptions>()!;

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = oidc.SchemeName;
            })
            .AddCookie(options =>
            {
                options.Cookie.Name = $"SignalHub.{oidc.SchemeName}";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                options.SlidingExpiration = true;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;

                options.Events.OnSigningOut = async context =>
                {
                    await Task.CompletedTask;
                };
            })
            .AddOpenIdConnect(oidc.SchemeName, o =>
            {
                o.Authority = oidc.Authority;
                o.ClientId = oidc.ClientId;
                o.ClientSecret = oidc.ClientSecret;
                o.ResponseType = oidc.ResponseType;
                o.ResponseMode = oidc.ResponseMode;
                o.MetadataAddress = oidc.MetadataAddress;
                o.CallbackPath = oidc.CallbackPath;
                o.SignedOutCallbackPath = oidc.SignedOutCallbackPath;
                o.RemoteSignOutPath = oidc.RemoteSignOutPath;
                o.SaveTokens = oidc.SaveTokens;
                o.UsePkce = oidc.RequirePkce;

                o.DisableTelemetry = true;
                o.MapInboundClaims = false;

                o.Scope.Clear();
                oidc.Scopes.ToList().ForEach(x => o.Scope.Add(x));

                if (oidc.RequestOfflineAccess && !o.Scope.Contains("offline_access"))
                {
                    o.Scope.Add("offline_access");
                }

                o.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = oidc.NameClaimType,
                    ValidateIssuer = true,
                    ValidIssuer = "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_rXuV2z4NL",
                    ValidateAudience = true,
                    ValidAudiences = string.IsNullOrEmpty(oidc.CognitoAppClientId)
                        ? new[] { oidc.ClientId }
                        : new[] { oidc.ClientId, oidc.CognitoAppClientId },
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true
                };

                o.ClaimsIssuer = oidc.SchemeName;
                o.ProtocolValidator.RequireNonce = false;

                o.Events = HubexoOpenIdEvents.Create(oidc.ClientId);
            })
            .AddJwtBearer(api.SchemeName, jwt =>
            {
                jwt.Authority = api.Authority;
                jwt.Audience = api.Audience;
                jwt.MetadataAddress = api.MetadataAddress;
                jwt.RequireHttpsMetadata = api.RequireHttpsMetadata;

                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = api.ValidateIssuer,
                    ValidateAudience = api.ValidateAudience,
                    ValidateLifetime = api.ValidateLifetime,
                    ValidateIssuerSigningKey = api.ValidateIssuerSigningKey,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                jwt.Events = HubexoJwtEvents.Create();
            });

            return services;
        }
    }
}
