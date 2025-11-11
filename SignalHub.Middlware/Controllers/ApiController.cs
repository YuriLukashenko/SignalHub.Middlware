using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SignalHub.Middlware.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = "HubexoBearer")]
public class ApiController : ControllerBase
{
    private readonly ILogger<ApiController> _logger;

    public ApiController(ILogger<ApiController> logger)
    {
        _logger = logger;
    }

    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        var userId = User.FindFirst("sub")?.Value;
        var email = User.FindFirst("email")?.Value;
        var name = User.Identity?.Name;

        _logger.LogInformation("API Profile request from user: {UserId}", userId);

        return Ok(new
        {
            UserId = userId,
            Email = email,
            Name = name,
            IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
            AuthenticationType = User.Identity?.AuthenticationType,
            Claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList()
        });
    }

    [HttpGet("claims")]
    public IActionResult GetClaims()
    {
        var userId = User.FindFirst("sub")?.Value;
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
        var userId = User.FindFirst("sub")?.Value;
        var email = User.FindFirst("email")?.Value;

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
        var userId = User.FindFirst("sub")?.Value;
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

    // Uncomment [Authorize(Roles = "Admin")] for role-based authorization
    [HttpGet("admin")]
    public IActionResult AdminOnly()
    {
        var userId = User.FindFirst("sub")?.Value;
        _logger.LogInformation("API Admin request from user: {UserId}", userId);

        var roles = User.Claims.Where(c => c.Type == "role" || c.Type == "roles")
            .Select(c => c.Value).ToList();

        return Ok(new
        {
            Message = "Admin endpoint - normally restricted to Admin role",
            UserId = userId,
            Roles = roles.Any() ? roles : new List<string> { "No roles found in token" }
        });
    }
}

public class CreateDataRequest
{
    public string Name { get; set; } = string.Empty;
    public int Value { get; set; }
}
