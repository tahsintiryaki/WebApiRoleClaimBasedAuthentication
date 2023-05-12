using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApiCalaimBasedAuthenticationTest.ActionFilter;
using WebApiCalaimBasedAuthenticationTest.Entity;
using WebApiCalaimBasedAuthenticationTest.RequestModel;

namespace WebApiCalaimBasedAuthenticationTest.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AccountController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                var role =await  _roleManager.FindByNameAsync("User");
               var roleClaims = await _roleManager.GetClaimsAsync(role);

                
                foreach (var userRole in roleClaims)
                {
                    authClaims.Add(new Claim(userRole.Type, userRole.Value));
                }

                var token = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new WebApiCalaimBasedAuthenticationTest.ResponseModel.Response { Status = "Error", Message = "User already exists!" });

            IdentityUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new WebApiCalaimBasedAuthenticationTest.ResponseModel.Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            return Ok(new WebApiCalaimBasedAuthenticationTest.ResponseModel.Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new WebApiCalaimBasedAuthenticationTest.ResponseModel.Response { Status = "Error", Message = "User already exists!" });

            IdentityUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new WebApiCalaimBasedAuthenticationTest.ResponseModel.Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            //if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            //{
            //    await _userManager.AddToRoleAsync(user, UserRoles.User);
            //}
            return Ok(new WebApiCalaimBasedAuthenticationTest.ResponseModel.Response { Status = "Success", Message = "User created successfully!" });
        }

       
        [HttpGet]
        [Authorize]
        [Authorize(AuthenticationSchemes = "Bearer", Policy = "TestMethod2Policy")]
        //[ServiceFilter(typeof(CheckPermissionActionFilter))] //2. yol=> Token içerisindeki ilgili claim var/yok kontrolü yapılır.
        public async Task<IActionResult> TestAction2()
        {
            //string token = _httpContextAccessor.HttpContext.Request.Headers["Authorization"];

            //var currentUser = ReadValueInToken(token);
            return Ok(new WebApiCalaimBasedAuthenticationTest.ResponseModel.Response { Status = "Success", Message = "Welcome to Application2" });

        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = "Bearer",Policy = "TestMethodPolicy")]
        //[ServiceFilter(typeof(CheckPermissionActionFilter))] //2. yol=> Token içerisindeki ilgili claim var/yok kontrolü yapılır.
        public async Task<IActionResult> Test()
        {

            return Ok(new WebApiCalaimBasedAuthenticationTest.ResponseModel.Response { Status = "Success", Message = "Welcome to Application" });

        }

        
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
    }
}

