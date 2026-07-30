using Backend.Db;
using Backend.Dto.RelEvent;
using Backend.Identity;
using Backend.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class UserTicketController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UserController> _logger;

    public UserTicketController(UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        ILogger<UserController> logger,
        IJwtService jwtService
        )
    {
        _userManager = userManager;
        _context = context;
        _logger = logger;
    }

    [HttpGet("user-tickets")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getUserBoughtTicketDto>> MyEvents()
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound("User not found");

            var events = await _context.UserEvents
               .AsNoTracking()
               .Where(ue => ue.UserId == userId)
               .Include(ue => ue.Event)
               .Select(ue => new getUserBoughtTicketDto
               {
                   eventId = ue.Event.Id,
                   typeOfEvent = ue.Event.TypeOfEvent,
                   nameOfEvent = ue.Event.NameOfEvent,
                   startOfEvent = ue.Event.StartOfEvent,
                   address = ue.Event.Address,
                   city = ue.Event.City,
                   nameOfClub = ue.Event.NameOfClub
               })
               .ToListAsync();

            if (!events.Any())
            {
                return NotFound("No events found for this user");
            }

            return Ok(events);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while getting user. tickets UserId: {UserId}", userId);
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpGet("ticket-detail-with-qr")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getEventQrCodeInfoDto>> TicketDetailsWithQr()
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound("User not found");

            var events = await _context.UserEvents
               .AsNoTracking()
               .Where(ue => ue.UserId == userId)
               .Include(ue => ue.Event)
               .Select(ue => new getEventQrCodeInfoDto
               {
                   eventId = ue.Event.Id,
                   typeOfEvent = ue.Event.TypeOfEvent,
                   nameOfEvent = ue.Event.NameOfEvent,
                   startOfEvent = ue.Event.StartOfEvent,
                   address = ue.Event.Address,
                   city = ue.Event.City,
                   nameOfClub = ue.Event.NameOfClub
               })
               .ToListAsync();

            if (!events.Any())
            {
                return NotFound("No events found for this user");
            }

            return Ok(events);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while getting user. tickets UserId: {UserId}", userId);
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

}
