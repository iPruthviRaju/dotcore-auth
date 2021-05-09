using Microsoft.AspNetCore.Mvc;

namespace AuthAspCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        [HttpGet]
        [Route("GetData")]
        public string GetData()
        {
            return "Auth Web API Core 5.0";
        }
    }
}
