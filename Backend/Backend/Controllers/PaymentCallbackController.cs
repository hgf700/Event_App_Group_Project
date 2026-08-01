using Backend.Db;
using Backend.Model;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using QRCoder;
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
    private readonly ILogger<PaymentCallbackController> _logger;

    public PaymentCallbackController(UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        QrCodeService qrCodeService,
        SmsService smsservice,
        EmailService emailService,
        OauthRefreshService oauthRefreshService,
        ILogger<PaymentCallbackController> logger
        )
    {
        _context = context;
        _userManager = userManager;
        _qrCodeService = qrCodeService;
        _smsservice = smsservice;
        _emailService = emailService;
        _logger = logger;
    }

    [HttpPost("payment-success/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
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
            var alreadyExists = await _context.UserEvents
                .AnyAsync(x => x.UserId == userId && x.EventId == id);

            if (alreadyExists)
                return BadRequest("Ticket already assigned");

            var userEvent = new UserEvent
            {
                EventId = ev.Id,
                UserId = userId
            };

            _context.UserEvents.Add(userEvent);
            await _context.SaveChangesAsync();

            bool.TryParse(Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE"), out bool twilio_sms_state);
            if (twilio_sms_state)
            {
                _smsservice.SendSMS(ev.UrlOfEvent);
            }

            var qrBytes = _qrCodeService.GenerateQrCodeBytes(ev.UrlOfEvent);

            var doc = new InvoiceDocument(
                eventName: ev.NameOfEvent,
                eventDate: ev.StartOfEvent.ToString(),
                eventAddress: ev.Address,
                eventType: ev.TypeOfEvent,
                eventUrl: ev.UrlOfEvent,
                qrCode: qrBytes
            );

            string resourcesPath = Path.Combine(Directory.GetCurrentDirectory(), "Resources");
            //Directory.CreateDirectory(resourcesPath); // na wszelki wypadek

            string pdfPath = Path.Combine(resourcesPath, "bilet.pdf");
            doc.GeneratePdf(pdfPath);

            string targetEmail = Environment.GetEnvironmentVariable("TARGET_EMAIL");
            _emailService.SendEmail(targetEmail, ev.UrlOfEvent);

            _logger.LogInformation("User successfully bought ticket {userId}", userId);

            return Ok();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while buying ticket for user: {UserId}", userId);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpPost("payment-failed")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult> PaymentFailed()
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        return Ok();
    }
}
