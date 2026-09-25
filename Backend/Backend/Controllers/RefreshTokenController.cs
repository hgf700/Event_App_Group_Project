using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Interfaces;
using EventApp.Services.Model;
using EventApp.Services.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
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

    [HttpPost("refresh")]
    public async Task<ActionResult> Refresh(string refreshToken)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var token = await _context.RefreshTokens
                .FirstOrDefaultAsync(x => x.UserId == userId && x.Expires < DateTime.UtcNow || x.Revoked != null);

            if (token == null)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(token.UserId);

            var newJwt = _jwtService.GenerateToken(user);

            return Ok(new
            {
                accessToken = newJwt
            });
        }
        catch (Exception ex) {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
