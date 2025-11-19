using Microsoft.AspNetCore.Mvc;

namespace SignalHub.Middlware.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class SignoutController : ControllerBase
    {
        private readonly ILogger<SignoutController> _logger;

        public SignoutController(ILogger<SignoutController> logger)
        {
            _logger = logger;
        }

        [HttpGet("complete")]
        public IActionResult SignoutComplete()
        {
            _logger.LogInformation("User has completed signout process");
            return Redirect("/signedout");
        }
    }
}
