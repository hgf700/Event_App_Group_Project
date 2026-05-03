using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto;
using Backend.Models.Model;
using Backend.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Stripe;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly JwtService _jwtService;

    public AuthController(UserManager<ApplicationUser> userManager, 
        ApplicationDbContext context,
        JwtService jwtService
        )
    {
        _userManager = userManager;
        _context = context;
        _jwtService = jwtService;
    }

    [HttpPost("register-norm")]
    public async Task<ActionResult<postCreateUserNormDto>> RegisterUserNormal([FromBody] postCreateUserNormDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var existingUser = await _userManager.FindByEmailAsync(dto.email);
        if (existingUser != null)
            return BadRequest("User already exists");

        try
        {
            var user = new ApplicationUser
            {
                UserName = dto.email,
                Email = dto.email,
                IsOAuth = false
            };

            //od razu hashuje haslo
            var result = await _userManager.CreateAsync(user, dto.password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            var jwt = _jwtService.GenerateToken(user);

            return Ok(new
            {
                token = jwt
            });

        }
        catch (Exception ex) 
        {
            //_logger.LogError(ex, "Register error");
            return BadRequest("register error");
        }
    }

    [HttpPost("login-norm")]
    public async Task<ActionResult> LoginUserNorm([FromBody] postLoginUserNormDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var existingUser = await _userManager.FindByEmailAsync(dto.email);

        if (existingUser == null)
            return Unauthorized("Invalid email or password");

        var validPassword = await _userManager.CheckPasswordAsync(existingUser, dto.password);

        if (!validPassword)
            return Unauthorized("Invalid email or password");

        var jwt = _jwtService.GenerateToken(existingUser);

        //return Redirect(
        //    $"http://localhost:4200/login-callback?token={jwt}"
        //);

        return Ok(new
        {
            token = jwt
        });
    }

    [HttpGet("sign-in-google")]
    public IActionResult SignInWithGoogle(string returnUrl = "/")
    {

        var redirectUrl = Url.Action(
            "GoogleResponse",
            "Auth",
            null,
            Request.Scheme
        );

        var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    [HttpGet("google-response")]
    public async Task<IActionResult> GoogleResponse()
    {
        //var authenticateResult = await HttpContext.AuthenticateAsync(
        //    GoogleDefaults.AuthenticationScheme);

        var authenticateResult = await HttpContext.AuthenticateAsync(
            IdentityConstants.ExternalScheme);

        if (!authenticateResult.Principal.Identities.Any(i => i.AuthenticationType == "Google"))
            return Unauthorized();

        if (!authenticateResult.Succeeded)
            return Unauthorized();

        var principal = authenticateResult.Principal;

        var email = principal.FindFirstValue(ClaimTypes.Email);
        var googleId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if (email == null)
            return BadRequest("Brak emaila z Google");

        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                IsOAuth=true
            };

            var createResult = await _userManager.CreateAsync(user);

            if (!createResult.Succeeded)
                return BadRequest(createResult.Errors);

            var loginInfo = new UserLoginInfo(
                "Google",
                googleId,
                "Google");

            await _userManager.AddLoginAsync(user, loginInfo);
        }

        var jwt = _jwtService.GenerateToken(user);

        return Redirect(
            $"http://localhost:4200/login-callback?token={jwt}"
        );
    }
}
