using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Interfaces;
using EventApp.Services.Patterns;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[Authorize(Roles = "admin,user")]
[Route("api/v1/event")]
public class EventController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<EventController> _logger;
    private readonly ISendOrDownloadFromApiService _downloadAndSendEventsApi;

    public EventController(
            ApplicationDbContext context,
            ILogger<EventController> logger,
            ISendOrDownloadFromApiService downloadAndSendEventsApi
        )
    {
        _context = context;
        _logger = logger;
        _downloadAndSendEventsApi = downloadAndSendEventsApi;
    }

    [AllowAnonymous]
    [HttpGet("public-get-events")]
    [EnableRateLimiting("GetPolicy")]
    [OutputCache(Duration = 60)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<paginatedResponse<getEventsDto>>> PublicGetEvents(int page = 1, int pageSize = 20)
    {
        try
        {
            var totalCount = await _context.Events.CountAsync();

            var events = await _context.Events
                .AsNoTracking()
                .OrderBy(e => e.Id)
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

            if (events == null)
                return NotFound();

            var response = new paginatedResponse<getEventsDto>
            {
                data = events,
                totalCount = totalCount,
                pageNumber = page,
                pageSize = pageSize
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while getting events.");
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpGet("get-events")]
    [EnableRateLimiting("GetPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<paginatedResponse<getEventsDto>>> GetEvents(int page = 1, int pageSize = 20)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null) 
            return Unauthorized();

        try
        {
            var totalCount = await _context.Events.CountAsync();

            var events = await _context.Events
                .AsNoTracking()
                .OrderBy(e => e.Id)
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

            if(events == null)
                return NotFound();

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

    [HttpGet("event-details/{id:int:min(0)}")]
    [EnableRateLimiting("GetPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getEventDetailsDto>> EventDetails(int id)
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

    private string NormalizeEvent(string value)
    {
        //bez to lower bo najpierw z bazy biore a potem api i tak samo robi pewnie to lower
        return new Pipe()
            .Add(new TrimFilter())
            .Add(new EmptyIfNullOrWhitespaceFilter())
            .Add(new NormalizeWhitespaceFilter())
            .Execute(new StringContext { Value = value })
            .Value!;
    }

    [HttpPost("search-event-and-download")]
    [EnableRateLimiting("PostPolicy")]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<List<postSearchOrDownloadQueryDto>>> SearchEventOrDownload([FromQuery] string? city,
    [FromBody] postSearchEventDto? body)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        var finalCity = city ?? body?.city;

        if (string.IsNullOrWhiteSpace(finalCity))
            return BadRequest("City is required");

        finalCity = NormalizeEvent(finalCity);

        try
        {
            var events = await _context.Events
                .Where(e => e.City == finalCity && e.StartOfEvent >= DateTime.UtcNow)
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

            if (downloadedEvents == null)
                return NotFound();

            return StatusCode(StatusCodes.Status201Created, downloadedEvents);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            _logger.LogError(ex, "Error while loading events");
            return StatusCode(500, "Internal server error");
        }
    }


}
