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

    public EventController(
            ApplicationDbContext context,
            QrCodeService qrCodeService,
            SmsService smsservice,
            EmailService emailService,
            UserManager<ApplicationUser> userManager,
            OauthRefreshService OauthRefreshService)
    {
        _context = context;
        _qrCodeService = qrCodeService;
        _smsservice = smsservice;
        _emailService = emailService;
        _userManager = userManager;
        _OauthRefreshService = OauthRefreshService;
    }


    [HttpGet("search-event")]
    public async Task<ActionResult> SearchEvent()
    {

        return Ok();
    }

}
