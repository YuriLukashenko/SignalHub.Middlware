using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SignalHub.Middlware.Components;
using SignalHub.Middlware.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddControllers();
builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug);

var hubexoOptions = new HubexoAuthenticationOptions
{
    Authority = builder.Configuration["HubexoID:Authority"] ?? "",
    ClientId = builder.Configuration["HubexoID:ClientId"] ?? "",
    ClientSecret = builder.Configuration["HubexoID:ClientSecret"] ?? "",
    CognitoAppClientId = builder.Configuration["HubexoID:CognitoAppClientId"],
    MetadataAddress = builder.Configuration["HubexoID:MetadataAddress"],
    CallbackPath = builder.Configuration["HubexoID:CallbackPath"] ?? "/signin-oidc-hubexo",
    SignedOutCallbackPath = builder.Configuration["HubexoID:SignedOutCallbackPath"] ?? "/signout/complete",
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
    options.Cookie.SameSite = SameSiteMode.Lax;
    
    options.Events.OnSigningOut = async context =>
    {
        await Task.CompletedTask;
    };
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
    oidcOptions.RemoteSignOutPath = "/signout-oidc-hubexo";
    oidcOptions.SaveTokens = hubexoOptions.SaveTokens;
    oidcOptions.UsePkce = true;
    oidcOptions.DisableTelemetry = true;

    oidcOptions.MapInboundClaims = false;

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
    oidcOptions.ProtocolValidator.RequireNonce = false;

    oidcOptions.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            context.ProtocolMessage.SetParameter("x-client-SKU", null);
            context.ProtocolMessage.SetParameter("x-client-ver", null);
            return Task.CompletedTask;
        },
        OnRedirectToIdentityProviderForSignOut = async context =>
        {
            // Візьмемо redirect із AuthenticationProperties, приведемо до абсолютного URL якщо потрібно
            var postLogoutUri = context.Properties?.RedirectUri;
            if (!string.IsNullOrEmpty(postLogoutUri) && postLogoutUri.StartsWith("/"))
            {
                var request = context.Request;
                postLogoutUri = $"{request.Scheme}://{request.Host}{request.PathBase}{postLogoutUri}";
            }

            if (!string.IsNullOrEmpty(postLogoutUri))
            {
                context.ProtocolMessage.PostLogoutRedirectUri = postLogoutUri;

                var idToken = await context.HttpContext.GetTokenAsync("id_token");
                if (!string.IsNullOrEmpty(idToken))
                {
                    context.ProtocolMessage.SetParameter("id_token_hint", idToken);
                }

                context.ProtocolMessage.SetParameter("client_id", hubexoOptions.ClientId);
            }

            await Task.CompletedTask;
        },

        OnRemoteSignOut = async context =>
        {
            await Task.CompletedTask;
        },
        OnSignedOutCallbackRedirect = async context =>
        {
            context.Response.Redirect(context.Options.SignedOutRedirectUri ?? "/");
            context.HandleResponse();
            await Task.CompletedTask;
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