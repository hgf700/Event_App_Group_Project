using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Model;
using EventApp.Services.Services.Interfaces;
using EventApp.Services.Services.model;
using EventApp.Services.Services.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using QuestPDF.Fluent;
using Stripe;
using Stripe.Checkout;


namespace EventApp.Services.Services;

public class PaymentService : IPaymentService
{
    private readonly ILogger<AuthService> _logger;
    private readonly ApplicationDbContext _context;
    private readonly IQrCodeService _qrCodeService;
    private readonly ISmsService _smsservice;
    private readonly IEmailService _emailService;
    private readonly string YOUR_DOMAIN = "http://localhost:4200";
    private readonly int AmountToPay = 1000;
    private readonly int TicketAmount = 1;


    public PaymentService(
        ILogger<AuthService> logger,
        ApplicationDbContext dbContext,
        IQrCodeService qrCodeService,
        ISmsService smsservice,
        IEmailService emailService
        )
    {
        _logger = logger;
        _context = dbContext;
        _qrCodeService = qrCodeService;
        _smsservice = smsservice;
        _emailService = emailService;
    }

    public async Task<BuyTicketResult> BuyTicketAsync(string userId, int id)
    {
        var ev = await _context.Events.FindAsync(id);

        if (ev == null)
        {
            return new BuyTicketResult
            {
                EventNotFound = true
            };
        }

        // Sprawdzamy tylko faktycznie opłacony zakup.
        var alreadyBought = await _context.UserEvents
            .AnyAsync(x =>
                x.UserId == userId &&
                x.EventId == id &&
                x.State == StatesOfTicket.Paid);

        if (alreadyBought)
        {
            return new BuyTicketResult
            {
                AlreadyBoughtTicket = true
            };
        }

        // Sprawdź, czy użytkownik ma już aktywną płatność.
        var pendingPurchase = await _context.UserEvents
            .FirstOrDefaultAsync(x =>
                x.UserId == userId &&
                x.EventId == id &&
                x.State == StatesOfTicket.Pending);

        if (pendingPurchase != null)
        {
            return new BuyTicketResult
            {
                Response = null,
                PaymentAlreadyPending = true
            };
        }

        StripeConfiguration.ApiKey = Environment.GetEnvironmentVariable("STRIP_SEC_KEY");

        if (string.IsNullOrWhiteSpace(StripeConfiguration.ApiKey))
        {
            _logger.LogError("Stripe secret key is missing");

            return new BuyTicketResult
            {
                Errors = new[]
                {
                    new IdentityError
                    {
                        Code = "MissingStripeKey",
                        Description = "Missing StripeKey."
                    }
                }
            };
        }

        // 1. Tworzymy zakup w bazie jako Pending
        var userEvent = new UserEvent
        {
            UserId = userId,
            EventId = ev.Id,
            CreatedAt = DateTime.UtcNow,
            State = StatesOfTicket.Pending
        };

        _context.UserEvents.Add(userEvent);

        await _context.SaveChangesAsync();

        // 2. Tworzymy Stripe Checkout Session
        var options = new SessionCreateOptions
        {
            Mode = "payment",

            ClientReferenceId = userEvent.Id.ToString(),

            Metadata = new Dictionary<string, string>
            {
                ["UserEventId"] = userEvent.Id.ToString(),
                ["UserId"] = userId,
                ["EventId"] = ev.Id.ToString()
            },

            LineItems = new List<SessionLineItemOptions>
            {
                new SessionLineItemOptions
                {
                    PriceData = new SessionLineItemPriceDataOptions
                    {
                        Currency = "pln",

                        UnitAmount = AmountToPay,

                        ProductData = new SessionLineItemPriceDataProductDataOptions
                        {
                            Name = ev.NameOfEvent
                        }
                    },
                    Quantity = TicketAmount
                }
            },
            SuccessUrl = $"{YOUR_DOMAIN}/payment-success?paymentId={userEvent.Id}",
            CancelUrl = $"{YOUR_DOMAIN}/payment-failed?paymentId={userEvent.Id}"
        };

        var service = new SessionService();

        Session session;

        try
        {
            session = await service.CreateAsync(options);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to create Stripe Checkout Session. UserId: {UserId}, EventId: {EventId}",
                userId,
                id);

            // Stripe nie utworzył płatności, więc Pending nie powinien zostać w bazie.
            userEvent.State = StatesOfTicket.Cancelled;
            userEvent.CancelledAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return new BuyTicketResult
            {
                Errors = new[]
                {
                    new IdentityError
                    {
                        Code = "StripeSessionCreationFailed",
                        Description = "Could not create payment session."
                    }
                }
            };
        }

        // 3. Zapisujemy Stripe Session ID
        userEvent.PaymentId = session.Id;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Stripe checkout session created. UserId: {UserId}, EventId: {EventId}, UserEventId: {UserEventId}, SessionId: {SessionId}",
            userId,
            id,
            userEvent.Id,
            session.Id);

        // 4. Zwracamy URL do Stripe
        return new BuyTicketResult
        {
            Response = session.Url,
            UserEventId = userEvent.Id,
        };
    }

    public async Task HandleSuccessfulPaymentAsync(Session session)
    {
        if (string.IsNullOrWhiteSpace(session.Id))
        {
            _logger.LogWarning("Stripe session ID is empty");
            return;
        }

        var userEvent = await _context.UserEvents
            .Include(x => x.Event)
            .FirstOrDefaultAsync(x => x.PaymentId == session.Id);

        if (userEvent == null)
        {
            _logger.LogError(
                "UserEvent not found for Stripe Session {SessionId}",
                session.Id);

            return;
        }

        // Webhook może zostać wysłany więcej niż raz. Dlatego nie wykonujemy drugi raz operacji.
        if (userEvent.State == StatesOfTicket.Paid)
        {
            _logger.LogInformation(
                "Payment already processed. SessionId: {SessionId}",
                session.Id);

            return;
        }

        userEvent.State = StatesOfTicket.Paid;
        userEvent.PaidAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        var ev = userEvent.Event;

        // Dopiero teraz użytkownik faktycznie kupił bilet
        bool.TryParse(Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE"), out bool twilioSmsState);

        if (twilioSmsState)
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

        Directory.CreateDirectory(resourcesPath);

        string pdfPath = Path.Combine(resourcesPath, $"ticket-{userEvent.Id}.pdf");

        doc.GeneratePdf(pdfPath);

        string? targetEmail = Environment.GetEnvironmentVariable("TARGET_EMAIL");

        if (!string.IsNullOrWhiteSpace(targetEmail))
        {
            _emailService.SendEmail(targetEmail, ev.UrlOfEvent);
        }

        _logger.LogInformation(
            "Payment successfully completed. UserEventId: {UserEventId}, UserId: {UserId}, EventId: {EventId}",
            userEvent.Id,
            userEvent.UserId,
            userEvent.EventId);
    }

    public async Task HandleExpiredPaymentAsync(Session session)
    {
        if (string.IsNullOrWhiteSpace(session.Id))
        {
            return;
        }

        var userEvent = await _context.UserEvents
            .FirstOrDefaultAsync(x => x.PaymentId == session.Id);

        if (userEvent == null)
        {
            _logger.LogWarning(
                "UserEvent not found for expired Stripe Session {SessionId}",
                session.Id);

            return;
        }

        if (userEvent.State != StatesOfTicket.Pending)
        {
            return;
        }

        userEvent.State = StatesOfTicket.Expired;
        userEvent.CancelledAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Payment expired. UserEventId: {UserEventId}, SessionId: {SessionId}",
            userEvent.Id,
            session.Id);
    }

}
