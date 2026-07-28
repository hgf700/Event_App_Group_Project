using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto.RelEvent;
using Backend.Models.Model;
using Backend.Patterns;
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
    private readonly SeedDbService _seedDbService;
    private readonly SendOrDownloadFromApiService _downloadAndSendEventsApi;
    private readonly ILogger<EventController> _logger;

    public EventController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            SeedDbService seedDbService,
            SendOrDownloadFromApiService downloadAndSendEventsApi,
            ILogger<EventController> logger
        )
    {
        _context = context;
        _userManager = userManager;
        _seedDbService= seedDbService;
        _downloadAndSendEventsApi = downloadAndSendEventsApi;
        _logger = logger;
    }

    [HttpGet("get-events")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<paginatedResponse<getEventsDto>>> GetEvents(
        int page = 1,
        int pageSize = 20)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null) 
            return Unauthorized();

        try
        {
            var totalCount = await _context.Events.CountAsync();

            var events = await _context.Events
                .AsNoTracking()
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(e => new getEventsDto
                {
                    eventId = e.Id,
                    typeOfEvent = e.TypeOfEvent,
                    nameOfEvent = e.NameOfEvent,
                    urlOfEvent = e.UrlOfEvent,
                    photoUrl = e.PhotoUrl,
                    startOfEvent = e.StartOfEvent,
                    address = e.Address,
                    city = e.City,
                    country = e.Country,
                    nameOfClub = e.NameOfClub
                })
                .ToArrayAsync();


            var response = new paginatedResponse<getEventsDto>
            {
                data = events,
                totalCount = totalCount,
                pageNumber = page,
                pageSize = pageSize
            };

            return Ok(response);
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

    [HttpPost("bookmark-event/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> BookmarkEvent(int id)
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

            return Ok();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while getting event details");
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
