using Backend.Db;
using Backend.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class BookmarkController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;

    public BookmarkController(ApplicationDbContext context, 
        UserManager<ApplicationUser> userManager
        )
    {
        _context = context;
        _userManager = userManager;
    }

    //do innej tabeli i dodac opcje na usuniecie 
    //[HttpPost("bookmark-event/{id}")]
    //[ProducesResponseType(StatusCodes.Status200OK)]
    //[ProducesResponseType(StatusCodes.Status400BadRequest)]
    //[ProducesResponseType(StatusCodes.Status401Unauthorized)]
    //[ProducesResponseType(StatusCodes.Status500InternalServerError)]
    //public async Task<ActionResult> BookmarkEvent(int id)
    //{
    //    if (!ModelState.IsValid)
    //        return BadRequest(ModelState);

    //    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    //    if (userId == null)
    //        return Unauthorized();

    //    try
    //    {
    //        var ev = await _context.Events.FindAsync(id);
    //        if (ev == null)
    //            return NotFound();

    //        return Ok();
    //    }
    //    catch (Exception ex)
    //    {
    //        Console.WriteLine(ex);
    //        _logger.LogError(ex, "Error while getting event details");
    //        return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
    //    }
    //}
}
