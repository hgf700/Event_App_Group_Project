using Backend.Db;
using Backend.Interfaces;
using Backend.Model;
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
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var token = await _context.RefreshTokens
                .FirstOrDefaultAsync(x => x.UserId == userId);

            if (token == null)
                return Unauthorized();

            if (token.Expires < DateTime.UtcNow)
                return Unauthorized();

            if (token.Revoked == true)
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
