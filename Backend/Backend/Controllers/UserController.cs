using Backend.Db;
using Backend.Dto.RelAuth;
using Backend.Dto.RelEvent;
using Backend.Interfaces;
using Backend.Model;
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
using Twilio.TwiML.Messaging;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class UserController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly IJwtService _jwtService;
    private readonly ILogger<UserController> _logger;

    public UserController(UserManager<ApplicationUser> userManager, 
        ApplicationDbContext context,
        ILogger<UserController> logger,
        IJwtService jwtService
        )
    {
        _userManager = userManager;
        _context = context;
        _logger = logger;
        _jwtService = jwtService;
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

    [HttpPost("edit-user-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> EditUserPassword([FromBody] postEditUserPassword body)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        if (string.IsNullOrWhiteSpace(body.oldPassword))
            return BadRequest("oldPassword password is required");

        if (string.IsNullOrWhiteSpace(body.newPassword))
            return BadRequest("newPassword password is required");

        try
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                _logger.LogWarning("User edit failed - user not found. UserId: {UserId}", userId);
                return NotFound("User not found");
            }

            var CheckCurrentPassword = await _userManager.CheckPasswordAsync(user, body.oldPassword);
            if (CheckCurrentPassword == false)
            {
                return BadRequest("Current password is invalid");
            }

            var passwordResult = await _userManager.ChangePasswordAsync(
                user,
                body.oldPassword,
                body.newPassword
            );

            if (!passwordResult.Succeeded)
                return BadRequest(passwordResult.Errors);

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            var userEmail= User.FindFirstValue(ClaimTypes.Email);

            _logger.LogInformation("User successfully edited {email}", userEmail);

            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while editing user. UserId: {UserId}", userId);
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpPost("edit-user-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<AuthResponseDto>> EditUserEmail([FromBody] string newEmail)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        if (string.IsNullOrWhiteSpace(newEmail))
            return BadRequest("newEmail is required");

        try
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                _logger.LogWarning("User edit failed - user not found. UserId: {UserId}", userId);
                return NotFound("User not found");
            }

            var emailExists = await _userManager.FindByEmailAsync(newEmail);

            if (emailExists != null)
                return BadRequest("Email already exists");

            user.Email = newEmail;
            user.UserName = newEmail; 

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            _logger.LogInformation("User successfully edited email {email}", newEmail);

            var token = _jwtService.GenerateToken(user);

            return Ok(new AuthResponseDto
            {
                jwt = token
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while editing user. UserId: {UserId}", userId);
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
