using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
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

// Configure HubexoID OIDC authentication (for web/Blazor)
var hubexoOptions = new HubexoAuthenticationOptions
{
    Authority = builder.Configuration["HubexoID:Authority"] ?? "",
    ClientId = builder.Configuration["HubexoID:ClientId"] ?? "",
    ClientSecret = builder.Configuration["HubexoID:ClientSecret"] ?? "",
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

// Configure HubexoID JWT Bearer authentication (for APIs)
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

// Dual authentication: Cookie+OIDC for web, JWT Bearer for APIs
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
    oidcOptions.MetadataAddress = hubexoOptions.MetadataAddress;
    oidcOptions.CallbackPath = hubexoOptions.CallbackPath;
    oidcOptions.SignedOutCallbackPath = hubexoOptions.SignedOutCallbackPath;
    oidcOptions.SaveTokens = hubexoOptions.SaveTokens;

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
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true
    };

    oidcOptions.ClaimsIssuer = hubexoOptions.SchemeName;

    oidcOptions.Events = new OpenIdConnectEvents
    {
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
            Console.WriteLine($"JWT Authentication failed: {context.Exception.Message}");
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Console.WriteLine($"JWT Token validated for: {context.Principal?.Identity?.Name}");
            return Task.CompletedTask;
        }
    };
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // HSTS value: 30 days. Adjust for production if needed: https://aka.ms/aspnetcore-hsts
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
