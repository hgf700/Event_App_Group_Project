using Backend.Db;
using Backend.Dto.RelEvent;
using Backend.Interfaces;
using Backend.Model;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net.Sockets;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class UserTicketController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UserController> _logger;
    private readonly QrCodeService _qrCodeService;


    public UserTicketController(UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        ILogger<UserController> logger,
        IJwtService jwtService,
        QrCodeService qrCodeService
        )
    {
        _userManager = userManager;
        _context = context;
        _logger = logger;
        _qrCodeService = qrCodeService;
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

    [HttpGet("ticket-detail-with-qr/{eventId}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getEventTicketWithQrDto>> TicketDetailsWithQr(int eventId)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId == null)
            return Unauthorized();

        var ticket = await _context.UserEvents
            .AsNoTracking()
            .Where(ue =>
                ue.UserId == userId &&
                ue.EventId == eventId)
            .Select(ue => new getEventTicketWithQrDto
            {
                eventId = ue.Event.Id,
                typeOfEvent = ue.Event.TypeOfEvent,
                nameOfEvent = ue.Event.NameOfEvent,
                startOfEvent = ue.Event.StartOfEvent,
                address = ue.Event.Address,
                city = ue.Event.City,
                nameOfClub = ue.Event.NameOfClub,
                urlOfEvent = ue.Event.UrlOfEvent
            })
            .FirstOrDefaultAsync();

        if (ticket == null)
            return NotFound("Ticket not found");

        ticket.qrCode = _qrCodeService.GenerateQrCodeBytes(ticket.urlOfEvent);

        return Ok(ticket);
    }
}
