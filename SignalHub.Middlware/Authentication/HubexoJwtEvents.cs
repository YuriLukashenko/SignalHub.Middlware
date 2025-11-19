using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace SignalHub.Middlware.Authentication
{
    public class HubexoJwtEvents
    {
        public static JwtBearerEvents Create()
        {
            return new JwtBearerEvents
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
        }
    }
}
