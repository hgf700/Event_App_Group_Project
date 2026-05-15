using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto.RelEvent;
using Backend.Models.Model;
using Backend.Resiliance;
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
using System.Text.Json;
using Twilio.Http;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class EventController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly DownloadFromApi _seedDbService;
    private readonly ILogger<EventController> _logger;
    private readonly ApiClient _apiClient;


    public EventController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            DownloadFromApi seedDbService,
            ILogger<EventController> logger,
            ApiClient apiClient
        )
    {
        _context = context;
        _userManager = userManager;
        _seedDbService= seedDbService;
        _logger = logger;
        _apiClient= apiClient;
    }

    [HttpGet("get-events")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<List<getEventsDto>>> GetEvents(int id)
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
                eventId = ev.Id,
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
            _logger.LogError(ex, "Error while getting events.");
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
                eventId = ev.Id,
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
            _logger.LogError(ex, "Error while getting event details");
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    //[HttpPost("save-event")]
    //public async Task<IActionResult> SaveEvent(int id)
    //{
    //    var ev = await _context.Events.FindAsync(id);
    //    if (ev == null)
    //        return NotFound();

    //    // Tu można dodać logikę zapisywania eventu do profilu użytkownika
    //    TempData["Message"] = $"Event \"{ev.NameOfEvent}\" został zapisany.";
    //    return RedirectToAction("Details", new { id });
    //}

    [HttpPost("seed-database")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> SeedDatabase()
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

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
            _logger.LogError(ex, "Error while seeding db");
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    //tu nei wiem czy dobrze trzeba 
 
}
