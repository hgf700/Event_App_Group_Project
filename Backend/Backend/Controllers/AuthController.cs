using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Model;
using EventApp.Services.Services.Interface;
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
    private readonly ILogger<AuthController> _logger;
    private readonly IAuthService _authService;
    private readonly string YOUR_DOMAIN = "http://localhost:4200";

    public AuthController(
        ILogger<AuthController> logger,
        IAuthService authService
        )
    {
        _logger= logger;
        _authService = authService;
    }

    [HttpPost("register-norm")]
    //[EnableRateLimiting("RateLimitGet")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<authResponseDto>> RegisterUserNormal([FromBody] postCreateUserNormDto dto)
    {
        try
        {
            var result = await _authService.RegisterNormalAsync(dto);

            if (result.UserAlreadyExists)
                return Conflict("User already exists");

            if (result.Errors != null)
                return BadRequest(result.Errors);

            return StatusCode(
                StatusCodes.Status201Created,
                result.Response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while registering user");

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpPost("login-norm")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> LoginUserNormal([FromBody] postLoginUserNormDto dto)
    {
        try
        {
            var result = await _authService.LoginNormalAsync(dto);

            if(result.IncorrectUserCredentials)
                return Unauthorized("Invalid email or password");

            return Ok(result.Response);
        }
        catch(Exception ex)
        {
            _logger.LogError(ex, "Error while logging user");

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
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

            if (authenticateResult?.Principal == null ||
                !authenticateResult.Succeeded)
            {
                _logger.LogWarning(
                    "Google OAuth authentication failed");

                return Unauthorized();
            }

            if (!authenticateResult.Principal.Identities
                .Any(i => i.AuthenticationType == "Google"))
            {
                _logger.LogWarning(
                    "Authentication type is not Google");

                return Unauthorized();
            }

            var result = await _authService.LoginGoogleOauth(
                authenticateResult.Principal);

            if (result.Errors?.Any() == true)
            {
                _logger.LogWarning("Google OAuth login failed: {Errors}",
                    string.Join("; ",
                        result.Errors.Select(e => $"{e.Code}: {e.Description}")
                    ));

                return BadRequest("Google login failed");
            }

            return Redirect(
                $"{YOUR_DOMAIN}/login-callback" +
                $"?token={Uri.EscapeDataString(result.Response!.jwt)}" +
                $"&email={Uri.EscapeDataString(result.Response!.email)}" +
                $"&role={Uri.EscapeDataString(result.Response!.userRole)}"
                );
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Error while Google OAuth login");

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }
}
