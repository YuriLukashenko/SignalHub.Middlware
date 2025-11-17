using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignalHub.Middlware.Services;
using SignalHub.Middlware.Extensions;

namespace SignalHub.Middlware.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = "HubexoBearer")]
public class ApiController : ControllerBase
{
    private readonly ILogger<ApiController> _logger;
    private readonly IAuthenticationService _authService;

    public ApiController(
        ILogger<ApiController> logger,
        IAuthenticationService authService)
    {
        _logger = logger;
        _authService = authService;
    }

    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        var userId = HttpContext.GetUserId();
        var email = HttpContext.GetUserEmail();
        var name = HttpContext.GetUserName();

        _logger.LogInformation("API Profile request from user: {UserId}", userId);

        return Ok(new
        {
            UserId = userId,
            Email = email,
            Name = name,
            IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
            AuthenticationType = User.Identity?.AuthenticationType,
            Claims = HttpContext.GetAllClaims(),
            Roles = HttpContext.GetUserRoles()
        });
    }

    [HttpGet("claims")]
    public IActionResult GetClaims()
    {
        var userId = HttpContext.GetUserId();
        _logger.LogInformation("API Claims request from user: {UserId}", userId);

        var claims = User.Claims.Select(c => new
        {
            Type = c.Type,
            Value = c.Value,
            Issuer = c.Issuer
        }).ToList();

        return Ok(new
        {
            TotalClaims = claims.Count,
            Claims = claims
        });
    }

    [HttpGet("data")]
    public IActionResult GetData()
    {
        var userId = HttpContext.GetUserId();
        var email = HttpContext.GetUserEmail();

        _logger.LogInformation("API Data request from user: {UserId}", userId);

        return Ok(new
        {
            Message = "This is protected data from the API",
            UserId = userId,
            Email = email,
            Timestamp = DateTime.UtcNow,
            Data = new[]
            {
                new { Id = 1, Name = "Item 1", Value = 100 },
                new { Id = 2, Name = "Item 2", Value = 200 },
                new { Id = 3, Name = "Item 3", Value = 300 }
            }
        });
    }

    [HttpPost("data")]
    public IActionResult CreateData([FromBody] CreateDataRequest request)
    {
        var userId = HttpContext.GetUserId();
        _logger.LogInformation("API Create Data request from user: {UserId}", userId);

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { Error = "Name is required" });
        }

        return CreatedAtAction(nameof(GetData), new
        {
            Id = Random.Shared.Next(1000, 9999),
            Name = request.Name,
            Value = request.Value,
            CreatedBy = userId,
            CreatedAt = DateTime.UtcNow
        });
    }

    [HttpGet("health")]
    [AllowAnonymous]
    public IActionResult Health()
    {
        return Ok(new
        {
            Status = "Healthy",
            Timestamp = DateTime.UtcNow,
            Authenticated = User.Identity?.IsAuthenticated ?? false,
            User = User.Identity?.Name
        });
    }

    [HttpGet("admin")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnly()
    {
        var userId = HttpContext.GetUserId();
        _logger.LogInformation("API Admin request from user: {UserId}", userId);

        return Ok(new
        {
            Message = "Admin endpoint - restricted to Admin role",
            UserId = userId,
            Roles = HttpContext.GetUserRoles()
        });
    }

    [HttpPost("signout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest? request = null)
    {
        var userId = HttpContext.GetUserId();
        _logger.LogInformation("API Logout request from user: {UserId}", userId);

        var logoutUrl = _authService.GetLogoutUrl(request?.ReturnUrl);

        await _authService.RevokeTokensAsync(HttpContext);

        return Ok(new
        {
            Success = true,
            Message = "Logout initiated successfully",
            LogoutUrl = logoutUrl,
            UserId = userId,
            Timestamp = DateTime.UtcNow
        });
    }

    [HttpGet("token-info")]
    public async Task<IActionResult> GetTokenInfo()
    {
        var userId = HttpContext.GetUserId();
        _logger.LogInformation("API Token Info request from user: {UserId}", userId);

        var tokens = await HttpContext.GetAllTokensAsync();
        var expiration = await HttpContext.GetTokenExpirationAsync();
        var isExpired = await HttpContext.IsTokenExpiredAsync();

        return Ok(new
        {
            UserId = userId,
            HasAccessToken = tokens.ContainsKey("access_token"),
            HasRefreshToken = tokens.ContainsKey("refresh_token"),
            HasIdToken = tokens.ContainsKey("id_token"),
            TokenExpiration = expiration,
            IsExpired = isExpired,
            Timestamp = DateTime.UtcNow
        });
    }

    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken()
    {
        var userId = HttpContext.GetUserId();
        _logger.LogInformation("API Revoke Token request from user: {UserId}", userId);

        try
        {
            await _authService.RevokeTokensAsync(HttpContext);
            
            return Ok(new
            {
                Success = true,
                Message = "Tokens revoked successfully",
                UserId = userId,
                Timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking tokens for user: {UserId}", userId);
            
            return StatusCode(500, new
            {
                Success = false,
                Message = "Failed to revoke tokens",
                Error = ex.Message
            });
        }
    }

    [HttpGet("session-info")]
    public async Task<IActionResult> GetSessionInfo()
    {
        var userId = HttpContext.GetUserId();
        var isAuthenticated = await HttpContext.IsAuthenticatedAsync();
        
        return Ok(new
        {
            IsAuthenticated = isAuthenticated,
            UserId = userId,
            UserName = HttpContext.GetUserName(),
            Email = HttpContext.GetUserEmail(),
            Roles = HttpContext.GetUserRoles(),
            SessionId = HttpContext.Session?.Id,
            Timestamp = DateTime.UtcNow
        });
    }
}

public class CreateDataRequest
{
    public string Name { get; set; } = string.Empty;
    public int Value { get; set; }
}

public class LogoutRequest
{
    public string? ReturnUrl { get; set; }
    public bool? RevokeTokens { get; set; } = true;
}