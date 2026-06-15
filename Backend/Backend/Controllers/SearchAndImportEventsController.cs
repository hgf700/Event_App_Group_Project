using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto.RelEvent;
using Backend.Patterns;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class SearchAndImportEventsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    //private readonly DownloadFromApi _seedDbService;
    private readonly ILogger<SearchAndImportEventsController> _logger;

    public SearchAndImportEventsController(ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            //DownloadFromApi seedDbService,
            ILogger<SearchAndImportEventsController> logger
        )
    {
        _context = context;
        _userManager = userManager;
        //_seedDbService = seedDbService;
        _logger = logger;
    }

    //nie moge to lower poniewaz najpierw pytam z bazy a w bazie mam z duzej 1 a potem z api a api i tak pewnie robi to lower
    private string NormalizeEvent(string? value)
    {
        return new Pipe()
            .Add(new TrimFilter())
            .Add(new EmptyIfNullOrWhitespaceFilter())
            .Add(new NormalizeWhitespaceFilter())
            .Execute(new StringContext { Value = value })
            .Value!;
    }

    // do poprawy napisane w todo i zrobic logger przt ex i pod koniec information success
    //[HttpGet("search-event")]
    //[ProducesResponseType(StatusCodes.Status200OK)]
    //[ProducesResponseType(StatusCodes.Status400BadRequest)]
    //[ProducesResponseType(StatusCodes.Status401Unauthorized)]
    //[ProducesResponseType(StatusCodes.Status500InternalServerError)]
    //public async Task<ActionResult<List<getEventsQueryDto>>> SearchEvent([FromQuery] string city)
    //{
    //    if (!ModelState.IsValid)
    //        return BadRequest(ModelState);

    //    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    //    if (userId == null)
    //        return Unauthorized();
        
    //    if (string.IsNullOrWhiteSpace(city))
    //        return BadRequest("City is required.");

    //    try
    //    {
    //        city = NormalizeEvent(city);

    //        var events = await _context.Events
    //            .Where(e => e.City == city && e.StartOfEvent >= DateTime.UtcNow)
    //            .ToListAsync();

    //        if (!events.Any())
    //        {
    //            // do poprawy napisane w todo
    //            var dto = await _seedDbService.FetchAndSaveEventsAsync(city);

    //            dto
    //            .Select(ev => new getEventsQueryDto
    //            {
    //                eventId = ev.eventId,
    //                typeOfEvent = ev.typeOfEvent,
    //                nameOfEvent = ev.nameOfEvent,
    //                urlOfEvent = ev.urlOfEvent,
    //                photoUrl = ev.photoUrl,
    //                startOfEvent = ev.startOfEvent,
    //                address = ev.address,
    //                city = ev.city,
    //                country = ev.country,
    //                nameOfClub = ev.nameOfClub
    //            }).ToList();

    //            return Ok(dto);

    //        }
    //        else
    //        {
    //            var dto = events
    //            .Select(ev => new getEventsQueryDto
    //            {
    //                eventId = ev.Id,
    //                typeOfEvent = ev.TypeOfEvent,
    //                nameOfEvent = ev.NameOfEvent,
    //                urlOfEvent = ev.UrlOfEvent,
    //                photoUrl = ev.PhotoUrl,
    //                startOfEvent = ev.StartOfEvent,
    //                address = ev.Address,
    //                city = ev.City,
    //                country = ev.Country,
    //                nameOfClub = ev.NameOfClub
    //            }).ToList();

    //            return Ok(dto);
    //        }
    //    }
    //    catch (Exception ex)
    //    {
    //        Console.WriteLine(ex);
    //        _logger.LogError(ex, "Error while search and import ticket for UserId: {UserId}", userId);
    //        return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
    //    }
    //}

}
