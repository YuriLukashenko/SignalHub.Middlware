using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SignalHub.Middlware.Models;

namespace SignalHub.Middlware.Extensions
{
    public static class AuthenticationExtensions
    {
        public static AuthenticationBuilder AddHubexoAuthentication(
            this IServiceCollection services,
            HubexoAuthenticationOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            options.Validate();

            if (options.RequestOfflineAccess && !options.Scopes.Contains("offline_access"))
            {
                options.Scopes.Add("offline_access");
            }

            var authBuilder = services.AddAuthentication(authOptions =>
            {
                authOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultChallengeScheme = options.SchemeName;
            })
            .AddCookie(cookieOptions =>
            {
                cookieOptions.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                cookieOptions.SlidingExpiration = true;
                cookieOptions.Cookie.Name = $"SignalHub.{options.SchemeName}";
                cookieOptions.Cookie.HttpOnly = true;
                cookieOptions.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            })
            .AddOpenIdConnect(options.SchemeName, oidcOptions =>
            {
                oidcOptions.Authority = options.Authority;
                oidcOptions.ClientId = options.ClientId;
                oidcOptions.ClientSecret = options.ClientSecret;
                oidcOptions.ResponseType = options.ResponseType;
                oidcOptions.ResponseMode = OpenIdConnectResponseMode.Query;
                oidcOptions.MetadataAddress = options.MetadataAddress;
                oidcOptions.CallbackPath = options.CallbackPath;
                oidcOptions.SignedOutCallbackPath = options.SignedOutCallbackPath;
                oidcOptions.SaveTokens = options.SaveTokens;
                oidcOptions.UsePkce = true;
                oidcOptions.DisableTelemetry = true;

                oidcOptions.Scope.Clear();
                foreach (var scope in options.Scopes)
                {
                    oidcOptions.Scope.Add(scope);
                }

                oidcOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = options.NameClaimType,
                    ValidateIssuer = false,
                    ValidateAudience = true,
                    ValidAudiences = string.IsNullOrEmpty(options.CognitoAppClientId)
                        ? new[] { options.ClientId }
                        : new[] { options.ClientId, options.CognitoAppClientId },
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true
                };

                oidcOptions.ClaimsIssuer = options.SchemeName;
                oidcOptions.ProtocolValidator.RequireNonce = false;

                oidcOptions.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        context.ProtocolMessage.SetParameter("x-client-SKU", null);
                        context.ProtocolMessage.SetParameter("x-client-ver", null);
                        return Task.CompletedTask;
                    },
                    OnRedirectToIdentityProviderForSignOut = context =>
                    {
                        var logoutUri = options.Authority.TrimEnd('/') + "/v2/logout?client_id=" + options.ClientId;
                        var postLogoutUri = context.Properties.RedirectUri;
                        if (!string.IsNullOrEmpty(postLogoutUri))
                        {
                            if (postLogoutUri.StartsWith("/"))
                            {
                                var request = context.Request;
                                postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                            }
                            logoutUri += $"&returnTo={Uri.EscapeDataString(postLogoutUri)}";
                        }

                        context.Response.Redirect(logoutUri);
                        context.HandleResponse();

                        return Task.CompletedTask;
                    },
                    OnRemoteFailure = context =>
                    {
                        context.Response.Redirect("/error");
                        context.HandleResponse();
                        return Task.CompletedTask;
                    }
                };
            });

            return authBuilder;
        }

        public static AuthenticationBuilder AddHubexoApiAuthentication(
            this IServiceCollection services,
            HubexoApiAuthenticationOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            options.Validate();

            var authBuilder = services.AddAuthentication(authOptions =>
            {
                authOptions.DefaultAuthenticateScheme = options.SchemeName;
                authOptions.DefaultChallengeScheme = options.SchemeName;
            })
            .AddJwtBearer(options.SchemeName, jwtOptions =>
            {
                jwtOptions.Authority = options.Authority;
                jwtOptions.Audience = options.Audience;
                jwtOptions.MetadataAddress = options.MetadataAddress;
                jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;

                jwtOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = options.ValidateIssuer,
                    ValidateAudience = options.ValidateAudience,
                    ValidateLifetime = options.ValidateLifetime,
                    ValidateIssuerSigningKey = options.ValidateIssuerSigningKey,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                jwtOptions.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        return Task.CompletedTask;
                    },
                    OnChallenge = context =>
                    {
                        return Task.CompletedTask;
                    }
                };
            });

            return authBuilder;
        }

        public static AuthenticationBuilder AddMultiProviderAuthentication(
            this IServiceCollection services,
            Action<OpenIdConnectOptions> configureAuth0,
            Action<OpenIdConnectOptions> configureHubexo,
            string defaultProvider = "Auth0")
        {
            ArgumentNullException.ThrowIfNull(configureAuth0);
            ArgumentNullException.ThrowIfNull(configureHubexo);

            var authBuilder = services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = defaultProvider;
            })
            .AddCookie(options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                options.SlidingExpiration = true;
                options.Cookie.Name = "SignalHub.Auth";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            })
            .AddOpenIdConnect("Auth0", configureAuth0)
            .AddOpenIdConnect("HubexoID", configureHubexo);

            return authBuilder;
        }

        public static AuthenticationBuilder AddDualApiAuthentication(
            this IServiceCollection services,
            Action<JwtBearerOptions> configureJwtBearer,
            string defaultScheme = JwtBearerDefaults.AuthenticationScheme)
        {
            ArgumentNullException.ThrowIfNull(configureJwtBearer);

            var authBuilder = services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = defaultScheme;
                options.DefaultChallengeScheme = defaultScheme;
            })
            .AddJwtBearer(configureJwtBearer);

            return authBuilder;
        }
    }
}
