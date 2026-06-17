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
public class SearchOrDownloadController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly SeedDbService _seedDbService;
    private readonly SendOrDownloadFromApiService _downloadAndSendEventsApi;
    private readonly ILogger<EventController> _logger;

    public SearchOrDownloadController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            SeedDbService seedDbService,
            SendOrDownloadFromApiService downloadAndSendEventsApi,
            ILogger<EventController> logger
        )
    {
        _context = context;
        _seedDbService = seedDbService;
        _downloadAndSendEventsApi = downloadAndSendEventsApi;
        _logger = logger;
    }

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
            await _seedDbService.SeedDatabase();

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

    private string NormalizeEvent(string? value)
    {
        //bez to lower bo najpierw z bazy biore a potem api i tak samo robi pewnie to lower
        return new Pipe()
            .Add(new TrimFilter())
            .Add(new EmptyIfNullOrWhitespaceFilter())
            .Add(new NormalizeWhitespaceFilter())
            .Execute(new StringContext { Value = value })
            .Value!;
    }

    [HttpPost("search-event-or-download")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<List<postSearchOrDownloadQueryDto>>> SearchEventOrDownload(
        [FromQuery] string? city,
        [FromBody] SearchEventDto? body)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        var finalCity = city ?? body?.City;

        if (string.IsNullOrWhiteSpace(finalCity))
            return BadRequest("City is required");

        finalCity = NormalizeEvent(finalCity);

        try
        {
            var events = await _context.Events
                .Where(e => e.City == finalCity &&
                            e.StartOfEvent >= DateTime.UtcNow)
                .ToListAsync();

            if (events.Any())
            {
                return Ok(events.Select(e => new postSearchOrDownloadQueryDto
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
                }));
            }

            var downloadedEvents =
                await _downloadAndSendEventsApi.FetchAndSaveEventsAsync(finalCity);

            return Ok(downloadedEvents);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            _logger.LogError(ex, "Error while loading events");
            return StatusCode(500, "Internal server error");
        }
    }


}
