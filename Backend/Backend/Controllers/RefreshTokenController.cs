using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace Backend.Controllers;

[ApiController]
//[Authorize(Roles = "admin,user")]
[Route("api/v1/refresh-token")]
public class RefreshTokenController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;

    public RefreshTokenController(ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        IJwtService jwtService
        )
    {
        _context = context;
        _userManager = userManager;
        _jwtService = jwtService;
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

        return Ok(new postRefreshTokenResponse
        {
            accessToken = newAccessToken
        });
    }
}
