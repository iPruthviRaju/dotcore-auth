using AuthAspCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserProfileController : ControllerBase
    {
        private UserManager<ApplicationUser> _userManager;
        public UserProfileController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet]
        [Authorize]
        //GET : /api/UserProfile
        public async Task<Object> GetUserProfile()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity == null)
                return null;

            var userName = identity.Claims.First(c => c.Type == "UserName").Value;
            var user = await _userManager.FindByNameAsync(userName);
            return new
            {
                user.UserName,
                user.Email
            };
        }
    }
}