using Backend.Db;
using Backend.Dto.RelAuth;
using Backend.Identity;
using Backend.Interfaces;
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
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(UserManager<ApplicationUser> userManager, 
        IJwtService jwtService,
        ILogger<AuthController> logger
        )
    {
        _userManager = userManager;
        _jwtService = jwtService;
        _logger= logger;
    }

    // [EnableRateLimiting("RateLimitGet")]
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

            var token = _jwtService.GenerateToken(user);

            _logger.LogInformation("User successfully register {email}", dto.email);

            return Ok(new AuthResponseDto
            {
                jwt = token
            });

        }
        catch (Exception ex) 
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while register user");
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
            {
                _logger.LogWarning("Invalid login attempt for email {email}", dto.email);
                return Unauthorized("Invalid email or password");
            }

            var token = _jwtService.GenerateToken(existingUser);

            _logger.LogInformation("User successfully login {email}", dto.email);

            return Ok(new AuthResponseDto
            {
                jwt = token,
            });
        }
        catch (Exception ex) {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while login user");
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
            {
                _logger.LogWarning("Google OAuth failed - Principal is null");
                return Unauthorized();
            }

            if (!authenticateResult.Succeeded)
            {
                _logger.LogWarning("Google OAuth authentication failed");
                return Unauthorized();
            }

            if (!authenticateResult.Principal.Identities
                .Any(i => i.AuthenticationType == "Google"))
            {
                _logger.LogWarning("Authentication type is not Google");
                return Unauthorized();
            }

            var principal = authenticateResult.Principal;

            var email = principal.FindFirstValue(ClaimTypes.Email);
            var googleId = principal.FindFirstValue(ClaimTypes.NameIdentifier);


            if (string.IsNullOrWhiteSpace(email))
            {
                _logger.LogWarning("Google OAuth missing email claim");
                return BadRequest("Brak emaila z Google");
            }

            if (string.IsNullOrWhiteSpace(googleId))
            {
                _logger.LogWarning("Google OAuth missing Google ID");
                return BadRequest("Brak Google ID");
            }

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
                    _logger.LogWarning("Failed to create OAuth user for email {Email}",email);
                    return BadRequest(createResult.Errors);
                }

                var loginInfo = new UserLoginInfo(
                    "Google",
                    googleId,
                    "Google");

                var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);

                if (!addLoginResult.Succeeded)
                {
                    _logger.LogWarning("Failed to add Google login for user {UserId}",user.Id);
                    return BadRequest(addLoginResult.Errors);
                }
                _logger.LogInformation("OAuth user created successfully. UserId: {UserId}",user.Id);
            }

            var token = _jwtService.GenerateToken(user);

            _logger.LogInformation("User {UserId} logged in with Google OAuth",user.Id);

            return Redirect(
                $"http://localhost:4200/login-callback?token={token}&email={Uri.EscapeDataString(email)}"
            );
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while oauth");
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
