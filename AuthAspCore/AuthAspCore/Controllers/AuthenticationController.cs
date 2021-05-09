using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AuthAspCore.Authentication;

namespace AuthAspCore.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager , IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var role = string.IsNullOrEmpty(model?.Role) ? UserRoles.User : model.Role;
            var userExist = await userManager.FindByNameAsync(model.UserName);
            if (userExist != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = " User Already Exist" });

            ApplicationUser user = new ApplicationUser
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.UserName
            };

            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to register" });

            await RegisterRole(role, user);

            return Ok(new Response { Status = "Success", Message = "User Created Successfully" });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.UserName);
            if(user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var authSiginKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["JWT:Secret"]));
                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddDays(1),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSiginKey,SecurityAlgorithms.HmacSha256Signature)
                    );

                return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token),
                        ValidTo = token.ValidTo.ToString("yyyy-MM-ddThh:mm:ss")
                });
            }
            return Unauthorized();
        }

        private async Task RegisterRole(string role, ApplicationUser user)
        {
            if (!IsValidRole(role)) return;
            if (role.Equals(UserRoles.Admin))
            {
                await SeedRolesAsync();
            }
            if (await roleManager.RoleExistsAsync(role))
            {
                await userManager.AddToRolesAsync(user, new List<string>() { role });
            }
        }

        private bool IsValidRole(string role)
        {
            var roles = new string[]
            {
                UserRoles.User, UserRoles.Admin, UserRoles.DataScientists, UserRoles.Developers, UserRoles.Management, UserRoles.Traders
            };
            return roles.Any(role.Contains);
        }

        private async Task SeedRolesAsync()
        {
            await SeedRoleAsync(UserRoles.Admin);
            await SeedRoleAsync(UserRoles.User);
            await SeedRoleAsync(UserRoles.Traders);
            await SeedRoleAsync(UserRoles.DataScientists);
            await SeedRoleAsync(UserRoles.Developers);
            await SeedRoleAsync(UserRoles.Management);
        }

        private async Task SeedRoleAsync(string role)
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
}
