using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto;
using Backend.Models.Model;
using Backend.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Stripe;
using System.Security.Claims;
using Twilio.TwiML.Messaging;

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
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
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
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpPost("login-norm")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> LoginUserNorm([FromBody] postLoginUserNormDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var existingUser = await _userManager.FindByEmailAsync(dto.email);

        if (existingUser == null)
            return Unauthorized("Invalid email or password");

        try
        {
            var validPassword = await _userManager.CheckPasswordAsync(existingUser, dto.password);

            if (!validPassword)
                return Unauthorized("Invalid email or password");

            var jwt = _jwtService.GenerateToken(existingUser);

            return Ok(new
            {
                token = jwt
            });
        }
        catch (Exception ex) {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
        
    }

    [HttpGet("sign-in-google")]
    public ActionResult SignInWithGoogle(string returnUrl = "/")
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
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> GoogleResponse()
    {
        try
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(
                IdentityConstants.ExternalScheme);

            if (authenticateResult?.Principal == null)
                return Unauthorized();

            if (!authenticateResult.Succeeded)
                return Unauthorized();

            if (!authenticateResult.Principal.Identities
                .Any(i => i.AuthenticationType == "Google"))
            {
                return Unauthorized();
            }

            var principal = authenticateResult.Principal;

            var email = principal.FindFirstValue(ClaimTypes.Email);
            var googleId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrWhiteSpace(email))
                return BadRequest("Brak emaila z Google");

            if (string.IsNullOrWhiteSpace(googleId))
                return BadRequest("Brak Google ID");

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    IsOAuth = true
                };

                var createResult = await _userManager.CreateAsync(user);

                if (!createResult.Succeeded)
                {
                    return BadRequest(createResult.Errors);
                }

                var loginInfo = new UserLoginInfo(
                    "Google",
                    googleId,
                    "Google");

                var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);

                if (!addLoginResult.Succeeded)
                {
                    return BadRequest(addLoginResult.Errors);
                }
            }

            var jwt = _jwtService.GenerateToken(user);

            return Redirect(
                $"http://localhost:4200/login-callback?token={jwt}"
            );
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
