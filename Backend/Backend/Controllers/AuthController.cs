using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Services.Interface;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Superpower.Model;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/v1/auth")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IAuthService _authService;
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;


    private readonly string YOUR_DOMAIN = "http://localhost:4200";
    private readonly string RefreshTokenPath = "/api/v1/auth/refresh";
    private readonly string JwtPath = "/";
    private readonly SameSiteMode cookiesSettings = SameSiteMode.None;


    public AuthController(
        ILogger<AuthController> logger,
        IAuthService authService,
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        IJwtService jwtService
        )
    {
        _logger= logger;
        _authService = authService;
        _context= context;
        _userManager = userManager;
        _jwtService = jwtService;
    }

    private void SetJwtCookie(string jwt)
    {
        Response.Cookies.Append("jwt", jwt, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = cookiesSettings,
            Path = JwtPath,
            Expires = DateTimeOffset.UtcNow.AddDays(7),
            IsEssential = true
        });
    }

    private void SetRefreshTOkenCookie(string refershToken)
    {
        Response.Cookies.Append("refreshToken", refershToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = cookiesSettings,
            Expires = DateTimeOffset.UtcNow.AddDays(30),
            Path = RefreshTokenPath
        });
    }

    [HttpPost("register-norm")]
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

            SetJwtCookie(result.Response!.jwt);
            SetRefreshTOkenCookie(result.Response!.refreshToken);

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

            SetJwtCookie(result.Response!.jwt);
            SetRefreshTOkenCookie(result.Response!.refreshToken);

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
    public async Task<ActionResult<authResponseDto>> GoogleResponse()
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

            SetJwtCookie(result.Response!.jwt);
            SetRefreshTOkenCookie(result.Response!.refreshToken);

            return Redirect(
                $"{YOUR_DOMAIN}/login-callback" +
                $"&email={Uri.EscapeDataString(result.Response!.email)}" +
                $"&userRole={Uri.EscapeDataString(result.Response!.userRole)}"
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

    [AllowAnonymous]
    [HttpPost("refresh")]
    [EnableRateLimiting("PostPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<postRefreshTokenResponse>> Refresh()
    {
        if (!Request.Cookies.TryGetValue("refreshToken", out var refreshToken)
            || string.IsNullOrWhiteSpace(refreshToken))
        {
            return Unauthorized();
        }

        var storedToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(x =>
                x.Token == refreshToken &&
                x.Expires >= DateTime.UtcNow &&
                x.Revoked == null);

        if (storedToken == null)
            return Unauthorized();

        var user = await _userManager.FindByIdAsync(storedToken.UserId);

        if (user == null)
            return Unauthorized();

        var newAccessToken = await _jwtService.GenerateToken(user);

        SetJwtCookie(newAccessToken);

        return Ok();
    }

    [HttpPost("logout")]
    [EnableRateLimiting("PostPolicy")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> LogoutUser()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!string.IsNullOrEmpty(refreshToken))
            {
                var tokenEntity = await _context.RefreshTokens
                    .FirstOrDefaultAsync(t =>
                        t.Token == refreshToken &&
                        t.Revoked == null);

                if (tokenEntity != null)
                {
                    tokenEntity.Revoked = DateTime.UtcNow;
                    await _context.SaveChangesAsync();
                }
            }

            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = cookiesSettings,
                Path = RefreshTokenPath
            });

            Response.Cookies.Delete("jwt", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = cookiesSettings,
                Path = JwtPath
            });

            return Ok();
        }
        catch(Exception ex)
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while seeding db");
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
