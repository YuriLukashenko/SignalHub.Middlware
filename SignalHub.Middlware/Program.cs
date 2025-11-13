using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SignalHub.Middlware.Components;
using SignalHub.Middlware.Extensions;
using SignalHub.Middlware.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddControllers();
builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();

var hubexoOptions = new HubexoAuthenticationOptions
{
    Authority = builder.Configuration["HubexoID:Authority"] ?? "",
    ClientId = builder.Configuration["HubexoID:ClientId"] ?? "",
    ClientSecret = builder.Configuration["HubexoID:ClientSecret"] ?? "",
    CognitoAppClientId = builder.Configuration["HubexoID:CognitoAppClientId"],
    MetadataAddress = builder.Configuration["HubexoID:MetadataAddress"],
    CallbackPath = builder.Configuration["HubexoID:CallbackPath"] ?? "/signin-oidc-hubexo",
    SignedOutCallbackPath = builder.Configuration["HubexoID:SignedOutCallbackPath"] ?? "/signout-callback-oidc-hubexo",
    SchemeName = builder.Configuration["HubexoID:SchemeName"] ?? "HubexoID"
};

var scopes = builder.Configuration.GetSection("HubexoID:Scopes").Get<string[]>();
if (scopes != null && scopes.Length > 0)
{
    hubexoOptions.Scopes = new List<string>(scopes);
}

var hubexoApiOptions = new HubexoApiAuthenticationOptions
{
    Authority = builder.Configuration["HubexoAPI:Authority"] ?? "",
    Audience = builder.Configuration["HubexoAPI:Audience"] ?? "",
    MetadataAddress = builder.Configuration["HubexoAPI:MetadataAddress"],
    RequireHttpsMetadata = bool.Parse(builder.Configuration["HubexoAPI:RequireHttpsMetadata"] ?? "true"),
    ValidateIssuer = bool.Parse(builder.Configuration["HubexoAPI:ValidateIssuer"] ?? "true"),
    ValidateAudience = bool.Parse(builder.Configuration["HubexoAPI:ValidateAudience"] ?? "true"),
    ValidateLifetime = bool.Parse(builder.Configuration["HubexoAPI:ValidateLifetime"] ?? "true"),
    SchemeName = builder.Configuration["HubexoAPI:SchemeName"] ?? "HubexoBearer"
};

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = hubexoOptions.SchemeName;
})
.AddCookie(options =>
{
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
    options.Cookie.Name = $"SignalHub.{hubexoOptions.SchemeName}";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
})
.AddOpenIdConnect(hubexoOptions.SchemeName, oidcOptions =>
{
    oidcOptions.Authority = hubexoOptions.Authority;
    oidcOptions.ClientId = hubexoOptions.ClientId;
    oidcOptions.ClientSecret = hubexoOptions.ClientSecret;
    oidcOptions.ResponseType = hubexoOptions.ResponseType;
    oidcOptions.ResponseMode = OpenIdConnectResponseMode.Query;
    oidcOptions.MetadataAddress = hubexoOptions.MetadataAddress;
    oidcOptions.CallbackPath = hubexoOptions.CallbackPath;
    oidcOptions.SignedOutCallbackPath = hubexoOptions.SignedOutCallbackPath;
    oidcOptions.SaveTokens = hubexoOptions.SaveTokens;
    oidcOptions.UsePkce = true;
    oidcOptions.DisableTelemetry = true;

    oidcOptions.Scope.Clear();
    foreach (var scope in hubexoOptions.Scopes)
    {
        oidcOptions.Scope.Add(scope);
    }

    if (hubexoOptions.RequestOfflineAccess && !oidcOptions.Scope.Contains("offline_access"))
    {
        oidcOptions.Scope.Add("offline_access");
    }

    oidcOptions.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = hubexoOptions.NameClaimType,
        ValidateIssuer = true,
        ValidIssuer = "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_rXuV2z4NL",
        ValidateAudience = true,
        ValidAudiences = string.IsNullOrEmpty(hubexoOptions.CognitoAppClientId)
            ? new[] { hubexoOptions.ClientId }
            : new[] { hubexoOptions.ClientId, hubexoOptions.CognitoAppClientId },
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true
    };

    oidcOptions.ClaimsIssuer = hubexoOptions.SchemeName;

    // Cognito with PKCE doesn't require nonce validation
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
            var logoutUri = hubexoOptions.Authority.TrimEnd('/') + "/v2/logout?client_id=" + hubexoOptions.ClientId;
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
})
.AddJwtBearer(hubexoApiOptions.SchemeName, jwtOptions =>
{
    jwtOptions.Authority = hubexoApiOptions.Authority;
    jwtOptions.Audience = hubexoApiOptions.Audience;
    jwtOptions.MetadataAddress = hubexoApiOptions.MetadataAddress;
    jwtOptions.RequireHttpsMetadata = hubexoApiOptions.RequireHttpsMetadata;

    jwtOptions.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = hubexoApiOptions.ValidateIssuer,
        ValidateAudience = hubexoApiOptions.ValidateAudience,
        ValidateLifetime = hubexoApiOptions.ValidateLifetime,
        ValidateIssuerSigningKey = hubexoApiOptions.ValidateIssuerSigningKey,
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
        }
    };
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.MapStaticAssets();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapControllers();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
