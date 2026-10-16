using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Interfaces;
using EventApp.Services.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[Authorize(Roles = "admin,user")]
[Route("api/v1/user")]
public class UserController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserService _userService;
    private readonly ILogger<UserController> _logger;
    private readonly IQrCodeService _qrCodeService;
    private readonly ApplicationDbContext _context;


    public UserController(UserManager<ApplicationUser> userManager,
        IUserService userService,
        ILogger<UserController> logger,
        IQrCodeService qrCodeService,
        ApplicationDbContext context
        )
    {
        _userManager = userManager;
        _userService = userService;
        _logger = logger;
        _qrCodeService = qrCodeService;
        _context = context;
    }

    [HttpPost("edit-user-password")]
    [EnableRateLimiting("PostPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> EditUserPassword([FromBody] postEditUserPasswordDto dto)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId))
            return Unauthorized();

        if (string.IsNullOrWhiteSpace(dto.oldPassword))
            return BadRequest("Old password is required");

        if (string.IsNullOrWhiteSpace(dto.newPassword))
            return BadRequest("New password is required");

        try
        {
            var result = await _userService.EditUserPasswordAsync(
                userId,
                dto);

            if (result.UserNotFound)
            {
                _logger.LogWarning(
                    "User edit password failed - user not found. UserId: {UserId}",
                    userId);

                return NotFound("User not found");
            }

            if (result.IncorrectPassword)
            {
                return BadRequest("Incorrect password");
            }

            if (result.Errors?.Any() == true)
            {
                //_logger.LogWarning(result.Errors);
                return BadRequest("error");
            }

            _logger.LogInformation(
                "User successfully changed password. UserId: {UserId}",
                userId);

            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Error while editing user password. UserId: {UserId}",
                userId);

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpPost("edit-user-email")]
    [EnableRateLimiting("PostPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<authResponseDto>> EditUserEmail([FromBody] string newEmail)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        if (string.IsNullOrWhiteSpace(newEmail))
            return BadRequest("newEmail is required");

        try
        {
            var result = await _userService.EditUserEmailAsync(
                userId,
                newEmail);

            if (result.UserNotFound)
            {
                _logger.LogWarning(
                    "User edit password failed - user not found. UserId: {UserId}",
                    userId);

                return NotFound("User not found");
            }

            if (result.IncorrectEmail)
            {
                return BadRequest("Incorrect email");
            }

            if (result.Errors?.Any() == true)
            {
                //_logger.LogWarning(result.Errors);
                return BadRequest("error");
            }

            _logger.LogInformation(
                "User successfully changed password. UserId: {UserId}",
                userId);

            return Ok(result.Response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while editing user. UserId: {UserId}", userId);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpGet("user-tickets")]
    [EnableRateLimiting("GetPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getUserBoughtTicketDto>> MyEvents()
    {
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

    [HttpGet("ticket-detail-with-qr/{eventId:int:min(0)}")]
    [EnableRateLimiting("GetPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
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

        var userEmail = User.FindFirstValue(ClaimTypes.Email);
        if (userEmail == null)
            return Unauthorized();

        var ticket = await _context.UserEvents
            .AsNoTracking()
            .Where(ue =>
                ue.UserId == userId &&
                ue.EventId == eventId)
            .Select(ue => new getEventTicketWithQrDto
            {
                userEventId = ue.Id,
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

        string basePath = Directory.GetCurrentDirectory();
        string generatedPath = Path.Combine(basePath, "Generated");
        Directory.CreateDirectory(generatedPath);

        string fileNameQr = $"QR-{ticket.userEventId}.png";
        string filePathQr = Path.Combine(generatedPath, fileNameQr);

        if (System.IO.File.Exists(filePathQr))
        {
            ticket.qrCode = await System.IO.File.ReadAllBytesAsync(filePathQr);
        }
        else
        {
            ticket.qrCode = _qrCodeService.GenerateQrCode(ticket.urlOfEvent, ticket.userEventId, userEmail);

            await System.IO.File.WriteAllBytesAsync(filePathQr, ticket.qrCode);
        }

        return Ok(ticket);
    }

}
