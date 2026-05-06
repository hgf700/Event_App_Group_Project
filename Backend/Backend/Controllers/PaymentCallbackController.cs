using Backend.Db;
using Backend.Identity;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class PaymentCallbackController
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly QrCodeService _qrCodeService;
    private readonly SmsService _smsservice;
    private readonly EmailService _emailService;
    private readonly OauthRefreshService _OauthRefreshService;

    public PaymentCallbackController(UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        QrCodeService qrCodeService,
        SmsService smsservice,
        EmailService emailService,
        OauthRefreshService OauthRefreshService
        )
    {
        _context = context;
        _qrCodeService = qrCodeService;
        _smsservice = smsservice;
        _emailService = emailService;
        _userManager = userManager;
        _OauthRefreshService = OauthRefreshService;
    }

    //[HttpGet("PaymentSuccess")]
    //public async Task<IActionResult> PaymentSuccess([FromQuery] int id)
    //{
    //    var ev = await _context.Events.FindAsync(id);
    //    if (ev == null)
    //        return NotFound();

    //    var user = await _userManager.GetUserAsync(User);
    //    if (user == null)
    //        return Unauthorized();

    //    string accessToken;
    //    try
    //    {
    //        accessToken = await _OauthRefreshService.EnsureValidAccessTokenAsync(user.Id);
    //    }
    //    catch
    //    {
    //        // <<< POPRAWKA: Użyj Redirect zamiast RedirectToPage w kontrolerze MVC >>>
    //        return Redirect("/Identity/Account/Login"); // lub RedirectToAction("Login", "Account", new { area = "Identity" });
    //    }

    //    // Reszta logiki bez zmian
    //    var userEvent = new UserEvent
    //    {
    //        EventId = ev.Id,
    //        UserId = user.Id
    //    };
    //    _context.UserEvents.Add(userEvent);
    //    await _context.SaveChangesAsync();

    //    _qrService.GenerateQrCode(ev.UrlOfEvent);

    //    bool.TryParse(Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE"), out bool twilio_sms_state);
    //    if (twilio_sms_state)
    //    {
    //        _smsservice.SendSMS(ev.UrlOfEvent);
    //    }

    //    var doc = new InvoiceDocument(
    //        eventName: ev.NameOfEvent,
    //        eventDate: ev.StartOfEvent.ToString(),
    //        eventAddress: ev.Address,
    //        eventType: ev.TypeOfEvent
    //    );

    //    string resourcesPath = Path.Combine(Directory.GetCurrentDirectory(), "Resources");
    //    Directory.CreateDirectory(resourcesPath); // na wszelki wypadek
    //    string pdfPath = Path.Combine(resourcesPath, "bilet.pdf");
    //    doc.GeneratePdf(pdfPath);

    //    string docelowyemail = Environment.GetEnvironmentVariable("TARGET_EMAIL");
    //    _emailService.SendEmail(docelowyemail, ev.UrlOfEvent);

    //    ViewBag.Message = "Płatność zakończona sukcesem!";
    //    return View("Success");
    //}


    //[HttpGet("PaymentFailed")]
    //public IActionResult PaymentFailed()
    //{
    //    // Logika po nieudanej płatności
    //    ViewBag.Message = "Płatność nie powiodła się. Spróbuj ponownie.";
    //    return View("Failed"); // Zwróć widok "Failed.cshtml"
    //}
}
