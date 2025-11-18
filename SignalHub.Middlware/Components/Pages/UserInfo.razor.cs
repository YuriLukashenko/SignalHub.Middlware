namespace SignalHub.Middlware.Components.Pages
{
    public partial class UserInfo
    {
        private string GetClaimValue(System.Security.Claims.ClaimsPrincipal user, string claimType)
        {
            return user.Claims.FirstOrDefault(c => c.Type == claimType)?.Value ?? "N/A";
        }

        private string GetShortClaimType(string claimType)
        {
            var prefixes = new[]
            {
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/",
                "http://schemas.microsoft.com/ws/2008/06/identity/claims/",
                "http://schemas.microsoft.com/identity/claims/"
            };

            foreach (var prefix in prefixes)
            {
                if (claimType.StartsWith(prefix))
                {
                    return claimType.Substring(prefix.Length);
                }
            }

            return claimType;
        }

        private string FormatTimestamp(string? timestamp)
        {
            if (string.IsNullOrEmpty(timestamp) || timestamp == "N/A")
                return "N/A";

            if (long.TryParse(timestamp, out long unixTime))
            {
                var dateTime = DateTimeOffset.FromUnixTimeSeconds(unixTime).LocalDateTime;
                return dateTime.ToString("yyyy-MM-dd HH:mm:ss");
            }

            return timestamp;
        }
    }
}
