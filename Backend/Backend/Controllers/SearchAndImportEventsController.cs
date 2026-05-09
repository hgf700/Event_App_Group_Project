using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto.RelEvent;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class SearchAndImportEventsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly DownloadFromApi _seedDbService;
    
    public SearchAndImportEventsController(ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            DownloadFromApi seedDbService
        )
    {
        _context = context;
        _userManager = userManager;
        _seedDbService = seedDbService;
    }

    [HttpGet("search-event")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<List<getEventsQueryDto>>> SearchEvent([FromQuery] string city)
    {
        if (string.IsNullOrWhiteSpace(city))
            return BadRequest("City is required.");

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            city = city.Trim();

            var events = await _context.Events
                .Where(e => e.City == city && e.StartOfEvent >= DateTime.UtcNow)
                .ToListAsync();

            if (!events.Any())
            {
                var dto = await _seedDbService.FetchAndSaveEventsAsync(city);

                dto
                .Select(ev => new getEventsQueryDto
                {
                    eventId = ev.eventId,
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
            else
            {
                var dto = events
                .Select(ev => new getEventsQueryDto
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
                }).ToList();

                return Ok(dto);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
