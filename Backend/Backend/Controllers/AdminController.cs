using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Interfaces;
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
    private readonly ISeedDbService _seedDbService;
    private readonly string UserRole = "user";
    private readonly string AdminRole = "admin";

    public AdminController(ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        ILogger<UserController> logger,
        ISeedDbService seedDbService
        )
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
        _seedDbService = seedDbService;
    }

    [HttpPost("admin-seed-database")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<bool>> SeedDatabase()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            await _seedDbService.SeedDatabase();

            var response = await _context.Events.AnyAsync();

            return StatusCode(StatusCodes.Status201Created, response);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while seeding db");
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
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
                .FirstOrDefaultAsync(e => e.Id == id);

            if (ev == null)
                return NotFound();

            _context.Events.Remove(ev);
            await _context.SaveChangesAsync();

            return Ok();
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
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getAdminUserDto>> AdminGetUsers()
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

                result.Add(new getAdminUserDto
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

    [HttpGet("admin-search-user/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getAdminUserDto>> AdminSearchUser(string id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        if (string.IsNullOrWhiteSpace(id))
            return BadRequest();

        try
        {
            var user = await _userManager.Users
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.IsActive && u.Id == id);

            if (user == null)
                return NotFound();

            var roles = await _userManager.GetRolesAsync(user);

            var response = new getAdminUserDto
            {
                id = user.Id,
                email = user.Email,
                userName = user.UserName,
                roles = roles
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

    [HttpPost("admin-delete-user/{id}")]
    //[EnableRateLimiting("RateLimitGet")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> AdminDeleteUser(string id)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            if (string.IsNullOrWhiteSpace(id))
                return BadRequest();

            var result = await _userManager.DeleteAsync(user);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    _logger.LogError(
                        "Error deleting user {UserId}: {Code} - {Description}",
                        id,
                        error.Code,
                        error.Description);
                }

                return StatusCode(
                    StatusCodes.Status500InternalServerError,
                    "Failed to delete user");
            }

            return Ok(new
            {
                message = "User deleted successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while deleting user {UserId}", id);

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpPost("admin-block-user/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> AdminBlockUser(string id)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            if (string.IsNullOrWhiteSpace(id))
                return BadRequest();

            if(user.IsActive == true)
            {
                user.IsActive = false;
            }
            else
            {
                return BadRequest();
            }

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                _logger.LogError(
                    "Failed to block user {UserId}: {Errors}",
                    id,
                    string.Join(", ", result.Errors.Select(e => e.Description)));

                return StatusCode(
                    StatusCodes.Status500InternalServerError,
                    "Failed to block user");
            }

            return Ok(new
            {
                message = "User blocked successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while blocked user {UserId}", id);

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpGet("admin-blocked-users")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getAdminUserDto>> AdminGetBlockedUsers()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var users = await _userManager.Users
                .AsNoTracking()
                .Where(u => u.IsActive == false)
                .ToListAsync();

            var result = new List<object>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);

                result.Add(new getAdminUserDto
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

    [HttpPost("admin-unblock-user/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> AdminUnblockUser(string id)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            if (user.IsActive == false)
            {
                user.IsActive = true;
            }
            else
            {
                return BadRequest();
            }

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                _logger.LogError(
                    "Failed to unblock user {UserId}: {Errors}",
                    id,
                    string.Join(", ", result.Errors.Select(e => e.Description)));

                return StatusCode(
                    StatusCodes.Status500InternalServerError,
                    "Failed to unblock user");
            }

            return Ok(new
            {
                message = "User unblock successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while unblock user {UserId}", id);

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpGet("admin-bought-tickets")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getAdminUserDto>> AdminBoughtTickets()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var users = await _userManager.Users
                .AsNoTracking()
                .Where(u => u.IsActive == false)
                .ToListAsync();

            var result = new List<object>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);

                result.Add(new getAdminUserDto
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
