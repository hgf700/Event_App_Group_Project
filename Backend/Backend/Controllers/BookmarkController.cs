using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelBookmark;
using EventApp.Services.Dto.RelEvent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[Authorize(Roles = "admin,user")]
[Route("api/v1/bookmark")]
public class BookmarkController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<BookmarkController> _logger;

    public BookmarkController(
        ApplicationDbContext context, 
        UserManager<ApplicationUser> userManager,
        ILogger<BookmarkController> logger
        )
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpGet("user-bookmarks")]
    [EnableRateLimiting("GetPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getBookmarkDto>> GetBookmark()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var bookmark = await _context.Bookmarks
                .AsNoTracking()
                .Include(b => b.Event)
                .Select(e => new getBookmarkDto
                {
                    id = e.Id,
                    userId = e.UserId,
                    eventId = e.EventId,
                    eventName = e.Event.NameOfEvent,
                })
                .ToArrayAsync();

            if (bookmark == null)
                return NotFound();

            return Ok(bookmark);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while getting bookmark details");
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpPost("bookmark-event/{eventId:int:min(0)}")]
    [EnableRateLimiting("PostPolicy")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> BookmarkEvent(int eventId)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId == null)
            return Unauthorized();

        try
        {
            var eventExists = await _context.Events
                .AnyAsync(e => e.Id == eventId);

            if (!eventExists)
                return NotFound("Event not found.");

            var alreadyBookmarked = await _context.Bookmarks
                .AnyAsync(b => b.EventId == eventId && b.UserId == userId);

            if (alreadyBookmarked)
                return Conflict("Event already bookmarked.");

            var bookmark = new Bookmark
            {
                UserId = userId,
                EventId = eventId
            };

            await _context.Bookmarks.AddAsync(bookmark);
            await _context.SaveChangesAsync();

            return Created();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while bookmarking event {EventId}", eventId);

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpPost("unbookmark-event/{eventId:int:min(0)}")]
    [EnableRateLimiting("PostPolicy")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> UnBookmarkEvent(int eventId)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var bookmark = await _context.Bookmarks
                .FirstOrDefaultAsync(b =>
                    b.EventId == eventId &&
                    b.UserId == userId);

            if (bookmark == null)
                return NotFound("Bookmark not found.");

            _context.Bookmarks.Remove(bookmark);
            await _context.SaveChangesAsync();

            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Error while removing bookmark for event {EventId}",
                eventId);

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }
}
