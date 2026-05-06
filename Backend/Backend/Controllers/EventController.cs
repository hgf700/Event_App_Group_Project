using Backend.Db;
using Backend.Identity;
using Backend.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Stripe;
using Twilio.Http;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class EventController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly QrCodeService _qrCodeService;
    private readonly SmsService _smsservice;
    private readonly EmailService _emailService;
    private readonly OauthRefreshService _OauthRefreshService;
    private readonly SeedDbService _seedDbService;

    public EventController(
            ApplicationDbContext context,
            QrCodeService qrCodeService,
            SmsService smsservice,
            EmailService emailService,
            UserManager<ApplicationUser> userManager,
            OauthRefreshService OauthRefreshService,
            SeedDbService seedDbService
        )
    {
        _context = context;
        _qrCodeService = qrCodeService;
        _smsservice = smsservice;
        _emailService = emailService;
        _userManager = userManager;
        _OauthRefreshService = OauthRefreshService;
        _seedDbService= seedDbService; 
    }


    [HttpGet("search-event/{id}")]
    public async Task<ActionResult> SearchEvent(int id)
    {

        return Ok();
    }

    [HttpPost("seed-database")]
    public async Task<ActionResult> SeedDatabase()
    {
        try
        {
            await _seedDbService.FetchAndSaveEventsAsync();

            return Ok(new
            {
                message = "Database seeded successfully"
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new
            {
                message = "Error while seeding database",
                error = ex.Message
            });
        }
    }

}
