using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto.RelEvent;
using Backend.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Stripe;
using System.Security.Claims;
using Twilio.Http;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class EventController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly QrCodeService _qrCodeService;
    private readonly SmsService _smsservice;
    private readonly EmailService _emailService;
    private readonly OauthRefreshService _OauthRefreshService;
    private readonly SeedDbService _seedDbService;

    public EventController(
            ApplicationDbContext context,
            QrCodeService qrCodeService,
            SmsService smsservice,
            EmailService emailService,
            UserManager<ApplicationUser> userManager,
            OauthRefreshService OauthRefreshService,
            SeedDbService seedDbService
        )
    {
        _context = context;
        _qrCodeService = qrCodeService;
        _smsservice = smsservice;
        _emailService = emailService;
        _userManager = userManager;
        _OauthRefreshService = OauthRefreshService;
        _seedDbService= seedDbService; 
    }

    [HttpGet("get-events")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getEventsDto>> GetEvents(int id)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null) 
            return Unauthorized();

        try
        {
            var ev = await _context.Events.ToListAsync();

            var dto = ev.Select(ev => new getEventsDto
            {
                typeOfEvent = ev.TypeOfEvent,
                nameOfEvent=ev.NameOfEvent,
                urlOfEvent=ev.UrlOfEvent,
                photoUrl= ev.PhotoUrl,
                startOfEvent = ev.StartOfEvent,
                address = ev.Address,
                city = ev.City,
                country = ev.Country,
                nameOfClub = ev.NameOfClub
            }).ToList();

            return Ok(dto);
        }
        catch (Exception ex) {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpGet("event-details/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getEventDetailsDto>> EventDetails(int id)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var ev = await _context.Events.FindAsync(id);
            if (ev == null)
                return NotFound();

            var dto = new getEventDetailsDto
            {
                typeOfEvent = ev.TypeOfEvent,
                nameOfEvent = ev.NameOfEvent,
                urlOfEvent = ev.UrlOfEvent,
                photoUrl = ev.PhotoUrl,
                startOfEvent = ev.StartOfEvent,
                address = ev.Address,
                city = ev.City,
                country = ev.Country,
                nameOfClub = ev.NameOfClub
            };

            return Ok(dto);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    //tu nei wiem czy dobrze trzeba spr
    [HttpGet("search-event")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getEventsQueryDto>> SearchEvent([FromQuery] string city, int pageNumber = 1)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var ev = await _seedDbService.FetchAndSaveEventsAsync(city);

            var dto = ev.Select(ev => new getEventsQueryDto
            {
                typeOfEvent = ev.typeOfEvent,
                nameOfEvent = ev.nameOfEvent,
                urlOfEvent = ev.urlOfEvent,
                photoUrl = ev.photoUrl,
                startOfEvent = ev.startOfEvent,
                address = ev.address,
                city = ev.city,
                country = ev.country,
                nameOfClub = ev.nameOfClub
            }).ToList();

            return Ok(dto);

        }
        catch (Exception ex) {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpPost("seed-database")]
    public async Task<ActionResult> SeedDatabase()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            await _seedDbService.FetchAndSaveEventsAsync();

            return Ok(new
            {
                message = "Database seeded successfully"
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

}
