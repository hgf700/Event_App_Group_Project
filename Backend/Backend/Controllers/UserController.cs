using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto.RelAuth;
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
public class UserController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UserController> _logger;

    public UserController(UserManager<ApplicationUser> userManager, 
        ApplicationDbContext context,
        ILogger<UserController> logger
        )
    {
        _userManager = userManager;
        _context = context;
        _logger = logger;
    }

    private string NormalizeUser(string? value)
    {
        return new Pipe()
            .Add(new TrimFilter())
            .Add(new EmptyIfNullOrWhitespaceFilter())
            .Add(new NormalizeWhitespaceFilter())
            .Execute(new StringContext { Value = value })
            .Value!;
    }

    [HttpGet("current-user")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getCurrentUserDto>> MyAccount()
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
                return NotFound();

            var dto = new getCurrentUserDto
            {
                email = user.Email,
            };

            return Ok(dto);

        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while getting current user. email UserId: {UserId}", userId);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpGet("user-tickets")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getEventsDto>> MyEvents()
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
               .Where(ue => ue.UserId == userId)
               .Include(ue => ue.Event)
               .Select(ue => new getEventsDto
               {
                   eventId = ue.Event.Id,
                   typeOfEvent = ue.Event.TypeOfEvent,
                   nameOfEvent = ue.Event.NameOfEvent,
                   urlOfEvent = ue.Event.UrlOfEvent,
                   photoUrl = ue.Event.PhotoUrl,
                   startOfEvent = ue.Event.StartOfEvent,
                   address = ue.Event.Address,
                   city = ue.Event.City,
                   country = ue.Event.Country,
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
  
    [HttpPost("edit-user")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<postEditUserDto>> EditUser([FromBody] postEditUserDto model)
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
            {
                _logger.LogWarning("User edit failed - user not found. UserId: {UserId}",userId);
                return NotFound("User not found");
            }

            model.newEmail = NormalizeUser(model.newEmail);
            model.currentPassword = NormalizeUser(model.currentPassword);
            model.newPassword = NormalizeUser(model.newPassword);

            var emailExists = await _userManager.FindByEmailAsync(model.newEmail);

            if (emailExists != null)
                return BadRequest("Email already exists");

            user.Email = model.newEmail;
            user.UserName = model.newEmail; // nick = email

            if (string.IsNullOrWhiteSpace(model.currentPassword))
                return BadRequest("Current password is required");

            var passwordResult = await _userManager.ChangePasswordAsync(
                user,
                model.currentPassword,
                model.newPassword
            );

            if (!passwordResult.Succeeded)
                return BadRequest(passwordResult.Errors);

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            _logger.LogInformation("User successfully edited {email}", model.newEmail);

            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while editing user. UserId: {UserId}", userId);
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

}
