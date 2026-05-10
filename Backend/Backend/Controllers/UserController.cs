using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto.RelEvent;
using Backend.Models.Model;
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

    public UserController(UserManager<ApplicationUser> userManager, 
        ApplicationDbContext context
        )
    {
        _userManager = userManager;
        _context = context;
    }

    [HttpGet("me")]
    public async Task<ActionResult> MyAccount()
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            //var user = await _userManager.GetUserAsync(userId);
            return Ok();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpGet("my-tickets")]
    public async Task<ActionResult> MyEvents()
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            //var user = await _userManager.GetUserAsync(userId);

            //var events = await _context.UserEvents
            //    .Include(ue => ue.Event)
            //    .Where(ue => ue.UserId == user.Id)
            //    .ToListAsync();

            return Ok();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpGet("edit-user")]
    public async Task<ActionResult> EditUserView()
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            return Ok();

        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }


    [HttpPost("edit-user")]
    public async Task<ActionResult> EditUser()
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            //if (user.Email != model.Email)
            //    user.Email = model.Email;

            //var result = await _userManager.UpdateAsync(user);


            return Ok();

        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
}
