using Backend.Db;
using Backend.Identity;
using Backend.Models.Model;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using QuestPDF.Fluent;
using System.Security.Claims;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class PaymentCallbackController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly QrCodeService _qrCodeService;
    private readonly SmsService _smsservice;
    private readonly EmailService _emailService;
    private readonly OauthRefreshService _oauthRefreshService;

    public PaymentCallbackController(UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        QrCodeService qrCodeService,
        SmsService smsservice,
        EmailService emailService,
        OauthRefreshService oauthRefreshService
        )
    {
        _context = context;
        _userManager = userManager;
        _qrCodeService = qrCodeService;
        _smsservice = smsservice;
        _emailService = emailService;
        _oauthRefreshService = oauthRefreshService;
    }

    [HttpPost("payment-success/{id}")]
    public async Task<ActionResult> PaymentSuccess(int id)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        var ev = await _context.Events.FindAsync(id);
        if (ev == null)
            return NotFound();

        try
        {
            string accessToken;
            accessToken = await _oauthRefreshService.EnsureValidAccessTokenAsync(userId);

            var userEvent = new UserEvent
            {
                EventId = ev.Id,
                UserId = userId
            };

            _context.UserEvents.Add(userEvent);
            await _context.SaveChangesAsync();

            _qrCodeService.GenerateQrCode(ev.UrlOfEvent);

            bool.TryParse(Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE"), out bool twilio_sms_state);
            if (twilio_sms_state)
            {
                _smsservice.SendSMS(ev.UrlOfEvent);
            }

            var doc = new InvoiceDocument(
                eventName: ev.NameOfEvent,
                eventDate: ev.StartOfEvent.ToString(),
                eventAddress: ev.Address,
                eventType: ev.TypeOfEvent
            );

            string resourcesPath = Path.Combine(Directory.GetCurrentDirectory(), "Resources");
            Directory.CreateDirectory(resourcesPath); // na wszelki wypadek

            string pdfPath = Path.Combine(resourcesPath, "bilet.pdf");
            doc.GeneratePdf(pdfPath);

            string docelowyemail = Environment.GetEnvironmentVariable("TARGET_EMAIL");
            _emailService.SendEmail(docelowyemail, ev.UrlOfEvent);

            return Ok();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }


    [HttpPost("payment-failed")]
    public ActionResult PaymentFailed()
    {
        return Ok();
    }
}
