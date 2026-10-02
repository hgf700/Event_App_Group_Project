using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Interfaces;
using EventApp.Services.Model;
using EventApp.Services.Services;
using EventApp.Services.Services.Interface;
using EventApp.Services.Services.Interfaces;
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
    private readonly IUserService _userService;
    private readonly ILogger<UserController> _logger;

    public UserController(UserManager<ApplicationUser> userManager,
        IUserService userService,
        ILogger<UserController> logger
        )
    {
        _userManager = userManager;
        _userService = userService;
        _logger = logger;
    }

    [HttpGet("current-user")]
    //[Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<getCurrentUserDto>> MyAccount()
    {
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
    //[Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> EditUserPassword([FromBody] postEditUserPasswordDto dto)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId))
            return Unauthorized();

        if (string.IsNullOrWhiteSpace(dto.oldPassword))
            return BadRequest("Old password is required");

        if (string.IsNullOrWhiteSpace(dto.newPassword))
            return BadRequest("New password is required");

        try
        {
            var result = await _userService.EditUserPasswordAsync(
                userId,
                dto);

            if (result.UserNotFound)
            {
                _logger.LogWarning(
                    "User edit password failed - user not found. UserId: {UserId}",
                    userId);

                return NotFound("User not found");
            }

            if (result.IncorrectPassword)
            {
                return BadRequest("Incorrect password");
            }

            if (result.Errors?.Any() == true)
            {
                //_logger.LogWarning(result.Errors);
                return BadRequest("error");
            }

            _logger.LogInformation(
                "User successfully changed password. UserId: {UserId}",
                userId);

            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Error while editing user password. UserId: {UserId}",
                userId);

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    [HttpPost("edit-user-email")]
    //[Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<authResponseDto>> EditUserEmail([FromBody] string newEmail)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        if (string.IsNullOrWhiteSpace(newEmail))
            return BadRequest("newEmail is required");

        try
        {
            var result = await _userService.EditUserEmailAsync(
                userId,
                newEmail);

            if (result.UserNotFound)
            {
                _logger.LogWarning(
                    "User edit password failed - user not found. UserId: {UserId}",
                    userId);

                return NotFound("User not found");
            }

            if (result.IncorrectEmail)
            {
                return BadRequest("Incorrect email");
            }

            if (result.Errors?.Any() == true)
            {
                //_logger.LogWarning(result.Errors);
                return BadRequest("error");
            }

            _logger.LogInformation(
                "User successfully changed password. UserId: {UserId}",
                userId);

            return Ok(result.Response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while editing user. UserId: {UserId}", userId);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
