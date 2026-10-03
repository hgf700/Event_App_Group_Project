using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Dto.RelEvent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Helpers;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[Authorize(Roles = "admin")]
[Route("api/v1/[controller]")]
public class AdminController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<UserController> _logger;

    public AdminController(ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        ILogger<UserController> logger
        )
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpGet("admin-app-info")]
    //[EnableRateLimiting("RateLimitGet")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getAppInfoDto>> GetAppInfo()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var userCount = await _userManager.Users
                .Where(u => u.IsActive)
                .AsNoTracking()
                .CountAsync();

            var boughtTickets = await _context.UserEvents
                .AsNoTracking()
                .CountAsync();

            var activeTickets = await _context.Events
                .AsNoTracking()
                .Where(e => e.StartOfEvent > DateTime.UtcNow)
                .CountAsync();

            var response = new getAppInfoDto
            {
                activeUserCount = userCount,
                boughtTickets= boughtTickets,
                activeTickets = activeTickets,
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while GetAppInfo");

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpGet("admin-events")]
    //[EnableRateLimiting("RateLimitGet")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getEventAdminDto>> AdminGetEvents()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var totalCount = await _context.Events.CountAsync();

            var events = await _context.Events
                .AsNoTracking()
                .Select(e => new getEventAdminDto
                {
                    id = e.Id,
                    nameOfEvent = e.NameOfEvent,
                    startOfEvent= e.StartOfEvent,
                    city= e.City,
                    nameOfClub= e.NameOfClub
                })
                .ToArrayAsync();

            if (events == null)
                return NotFound();

            return Ok(events);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while getting event details");

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpPost("admin-delete-event/{id:int:min(0)}")]
    //[EnableRateLimiting("RateLimitGet")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> AdminDeleteEvents(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var ev = await _context.Events
                .AsNoTracking()
                .FirstOrDefaultAsync(e => e.Id == id);

            if (ev == null)
                return NotFound();

            return Ok(ev);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while getting event details");

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpGet("admin-users")]
    //[EnableRateLimiting("RateLimitGet")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> AdminGetUsers()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var users = await _userManager.Users
                .AsNoTracking()
                .Where(u => u.IsActive)
                .ToListAsync();

            var result = new List<object>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);

                result.Add(new 
                {
                    id = user.Id,
                    email = user.Email,
                    userName = user.UserName,
                    roles = roles
                });
            }

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while GetAppInfo");

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

}
