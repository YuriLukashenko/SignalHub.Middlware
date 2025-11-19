using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace SignalHub.Middlware.Authentication
{
    public class HubexoOpenIdEvents
    {
        public static OpenIdConnectEvents Create(string clientId)
        {
            return new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = context =>
                {
                    context.ProtocolMessage.SetParameter("x-client-SKU", null);
                    context.ProtocolMessage.SetParameter("x-client-ver", null);
                    return Task.CompletedTask;
                },
                OnRedirectToIdentityProviderForSignOut = async context =>
                {
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

                        context.ProtocolMessage.SetParameter("client_id", clientId);
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
        }
    }
}
