using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Interfaces;
using EventApp.Services.Model;
using EventApp.Services.Services.Interfaces;
using EventApp.Services.Services.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Stripe;
using Stripe.Checkout;

namespace EventApp.Services.Services;

public class PaymentService : IPaymentService
{
    private readonly ILogger<PaymentService> _logger;
    private readonly ApplicationDbContext _context;
    private readonly IQrCodeService _qrCodeService;
    private readonly ISmsService _smsService;
    private readonly IEmailService _emailService;
    private readonly IPdfService _pdfService;
    private readonly UserManager<ApplicationUser> _userManager;


    private const string YourDomain = "http://localhost:4200";
    private const long AmountToPay = 1000;
    private const long TicketAmount = 1;

    public PaymentService(
        ILogger<PaymentService> logger,
        ApplicationDbContext dbContext,
        IQrCodeService qrCodeService,
        ISmsService smsService,
        IEmailService emailService,
        UserManager<ApplicationUser> userManager,
        IPdfService pdfService
        )
    {
        _logger = logger;
        _context = dbContext;
        _qrCodeService = qrCodeService;
        _smsService = smsService;
        _emailService = emailService;
        _userManager = userManager;
        _pdfService = pdfService;
    }

    public async Task<BuyTicketResult> BuyTicketAsync(string userId, int eventId)
    {
        var stripeSecretKey = Environment.GetEnvironmentVariable("STRIP_SEC_KEY");

        if (string.IsNullOrWhiteSpace(stripeSecretKey))
        {
            _logger.LogError("Stripe secret key is missing");

            return new BuyTicketResult
            {
                Errors = new[]
                {
                    new IdentityError
                    {
                        Code = "MissingStripeKey",
                        Description = "Missing Stripe secret key."
                    }
                }
            };
        }

        StripeConfiguration.ApiKey = stripeSecretKey;

        var ev = await _context.Events
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == eventId);

        if (ev == null)
        {
            return new BuyTicketResult { EventNotFound = true };
        }

        // Już opłacony bilet
        var alreadyBought = await _context.UserEvents
            .AnyAsync(x =>
                x.UserId == userId &&
                x.EventId == eventId &&
                x.PaymentState == StatesOfTicket.Paid);

        if (alreadyBought)
        {
            return new BuyTicketResult { AlreadyBoughtTicket = true };
        }

        // Już istnieje aktywna płatność Pending
        var pendingPurchase = await _context.UserEvents
            .FirstOrDefaultAsync(x =>
                x.UserId == userId &&
                x.EventId == eventId &&
                x.PaymentState == StatesOfTicket.Pending);

        if (pendingPurchase != null)
        {
            _logger.LogInformation(
                "Pending payment already exists. UserId: {UserId}, EventId: {EventId}, UserEventId: {UserEventId}",
                userId, eventId, pendingPurchase.Id);

            return new BuyTicketResult
            {
                PaymentAlreadyPending = true,
                UserEventId = pendingPurchase.Id
            };
        }

        // Tworzymy rekord Pending
        var userEvent = new UserEvent
        {
            UserId = userId,
            EventId = ev.Id,
            CreatedAt = DateTime.UtcNow,
            PaymentState = StatesOfTicket.Pending,
            PaymentStateAt = DateTime.UtcNow,
            TicketState = TicketState.NotIssued
        };

        _context.UserEvents.Add(userEvent);
        await _context.SaveChangesAsync();

        _logger.LogInformation("UserEvent created with Id = {Id}", userEvent.Id);

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
                new()
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
            SuccessUrl = $"{YourDomain}/payment-status?paymentId={userEvent.Id}",
            CancelUrl = $"{YourDomain}/payment-status?paymentId={userEvent.Id}&cancelled=true",

            // Opcjonalnie: wygaśnięcie sesji po 30 minutach
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        };

        var stripeService = new SessionService();
        Session session;

        try
        {
            session = await stripeService.CreateAsync(options);
        }
        catch (StripeException ex)
        {
            _logger.LogError(ex,
                "Failed to create Stripe Checkout Session. UserId: {UserId}, EventId: {EventId}, UserEventId: {UserEventId}",
                userId, eventId, userEvent.Id);

            userEvent.PaymentState = StatesOfTicket.Cancelled;
            userEvent.PaymentStateAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            return new BuyTicketResult
            {
                Errors = new[]
                {
                    new IdentityError
                    {
                        Code = "StripeSessionCreationFailed",
                        Description = "Could not create Stripe payment session."
                    }
                }
            };
        }

        // Zapisujemy SessionId
        userEvent.PaymentId = session.Id;
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Stripe Checkout Session created. UserId: {UserId}, EventId: {EventId}, UserEventId: {UserEventId}, SessionId: {SessionId}",
            userId, eventId, userEvent.Id, session.Id);

        return new BuyTicketResult
        {
            Response = session.Url,
            UserEventId = userEvent.Id
        };
    }

    public async Task HandleSuccessfulPaymentAsync(Session session)
    {
        if (session == null || string.IsNullOrWhiteSpace(session.Id))
        {
            _logger.LogWarning("Stripe session is null or empty");
            return;
        }

        if (!string.Equals(session.PaymentStatus, "paid", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "Checkout Session completed but payment is not paid. SessionId: {SessionId}, PaymentStatus: {PaymentStatus}",
                session.Id, session.PaymentStatus);
            return;
        }

        // 1. Szukamy po PaymentId (SessionId)
        var userEvent = await _context.UserEvents
            .Include(x => x.Event)
            .FirstOrDefaultAsync(x => x.PaymentId == session.Id);

        // 2. Fallback po metadata
        if (userEvent == null &&
            session.Metadata != null &&
            session.Metadata.TryGetValue("UserEventId", out var userEventIdValue) &&
            int.TryParse(userEventIdValue, out var userEventId))
        {
            userEvent = await _context.UserEvents
                .Include(x => x.Event)
                .FirstOrDefaultAsync(x => x.Id == userEventId);
        }

        if (userEvent == null)
        {
            _logger.LogError("UserEvent not found for Stripe Session {SessionId}", session.Id);
            return;
        }

        // Idempotencja
        if (userEvent.PaymentState == StatesOfTicket.Paid)
        {
            _logger.LogInformation(
                "Payment already processed. SessionId: {SessionId}, UserEventId: {UserEventId}",
                session.Id, userEvent.Id);
            return;
        }

        // Nie opłacamy anulowanych / expired
        if (userEvent.PaymentState != StatesOfTicket.Pending)
        {
            _logger.LogWarning(
                "Ignoring successful payment – UserEvent is not Pending. " +
                "SessionId: {SessionId}, UserEventId: {UserEventId}, State: {PaymentState}",
                session.Id, userEvent.Id, userEvent.PaymentState);
            return;
        }

        // Walidacja metadata
        if (session.Metadata != null)
        {
            if (session.Metadata.TryGetValue("UserId", out var metaUserId) &&
                metaUserId != userEvent.UserId)
            {
                _logger.LogError("Stripe UserId mismatch. SessionId: {SessionId}", session.Id);
                return;
            }

            if (session.Metadata.TryGetValue("EventId", out var metaEventId) &&
                int.TryParse(metaEventId, out var eventId) &&
                eventId != userEvent.EventId)
            {
                _logger.LogError("Stripe EventId mismatch. SessionId: {SessionId}", session.Id);
                return;
            }
        }

        // Oznaczamy jako Paid + Active
        userEvent.PaymentState = StatesOfTicket.Paid;
        userEvent.PaymentStateAt = DateTime.UtcNow;
        userEvent.TicketState = TicketState.Active;
        userEvent.TicketStateAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Payment marked as Paid. UserEventId: {UserEventId}, UserId: {UserId}, EventId: {EventId}",
            userEvent.Id, userEvent.UserId, userEvent.EventId);

        var ev = userEvent.Event;
        if (ev == null)
        {
            _logger.LogError("Event not found for UserEventId: {UserEventId}", userEvent.Id);
            return;
        }

        var user = await _userManager.FindByIdAsync(userEvent.UserId);
        string email = user.Email;

        // Wydanie biletu (SMS / QR / PDF / Email) – nie wpływa na status płatności

        await IssueTicketAsync(userEvent, ev, email);
    }

    public async Task HandleExpiredPaymentAsync(Session session)
    {
        if (session == null || string.IsNullOrWhiteSpace(session.Id))
        {
            _logger.LogWarning("Stripe session is null or empty");
            return;
        }

        var userEvent = await _context.UserEvents
            .FirstOrDefaultAsync(x => x.PaymentId == session.Id);

        if (userEvent == null)
        {
            _logger.LogWarning("UserEvent not found for expired Session {SessionId}", session.Id);
            return;
        }

        if (userEvent.PaymentState != StatesOfTicket.Pending)
        {
            _logger.LogInformation(
                "Ignoring expired webhook – UserEvent is not Pending. " +
                "SessionId: {SessionId}, UserEventId: {UserEventId}, State: {PaymentState}",
                session.Id, userEvent.Id, userEvent.PaymentState);
            return;
        }

        userEvent.PaymentState = StatesOfTicket.Expired;
        userEvent.PaymentStateAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Payment expired. UserEventId: {UserEventId}, SessionId: {SessionId}",
            userEvent.Id, session.Id);
    }

    public async Task HandleRefundedPaymentAsync(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
            return;

        var userEvent = await _context.UserEvents
            .FirstOrDefaultAsync(x => x.PaymentId == sessionId);

        if (userEvent == null)
        {
            _logger.LogWarning("UserEvent not found for refunded Session {SessionId}", sessionId);
            return;
        }

        if (userEvent.PaymentState == StatesOfTicket.Refunded)
            return;

        userEvent.PaymentState = StatesOfTicket.Refunded;
        userEvent.PaymentStateAt = DateTime.UtcNow;
        userEvent.TicketState = TicketState.Cancelled;
        userEvent.TicketStateAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Payment refunded. UserEventId: {UserEventId}, SessionId: {SessionId}",
            userEvent.Id, sessionId);
    }

    public async Task<bool> CancelPendingPaymentAsync(string userId, int userEventId)
    {
        var userEvent = await _context.UserEvents
            .FirstOrDefaultAsync(x =>
                x.Id == userEventId &&
                x.UserId == userId &&
                x.PaymentState == StatesOfTicket.Pending);

        if (userEvent == null)
            return false;

        userEvent.PaymentState = StatesOfTicket.Cancelled;
        userEvent.PaymentStateAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Pending payment cancelled by user. UserEventId: {UserEventId}, UserId: {UserId}",
            userEvent.Id, userId);

        return true;
    }

    // 6. Wydanie biletu (SMS + QR + PDF + Email)
    private async Task IssueTicketAsync(UserEvent userEvent, Domain.Model.Event ev, string email)
    {
        try
        {
            bool.TryParse(Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE"), out var sendSms);

            if (sendSms)
            {
                _smsService.SendSMS(ev.UrlOfEvent);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send SMS for UserEventId: {UserEventId}", userEvent.Id);
        }
        
        byte[] qrBytes;
        try
        {
            qrBytes = _qrCodeService.GenerateQrCode(ev.UrlOfEvent, userEvent.Id, email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate QR code for UserEventId: {UserEventId}", userEvent.Id);
            return; // bez QR nie generujemy PDF
        }

        try
        {
            await _pdfService.GeneratePdfAsync(
                eventName: ev.NameOfEvent,
                eventDate: ev.StartOfEvent.ToString(),
                eventAddress: ev.Address,
                eventType: ev.TypeOfEvent,
                eventUrl: ev.UrlOfEvent,
                email: email,
                userEventId: userEvent.Id,
                qrCode: qrBytes);

            _logger.LogInformation("Ticket PDF generated. UserEventId: {UserEventId}", userEvent.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate ticket PDF for UserEventId: {UserEventId}", userEvent.Id);
        }

        try
        {
            var targetEmail = Environment.GetEnvironmentVariable("TARGET_EMAIL");

            if (string.IsNullOrWhiteSpace(targetEmail))
            {
                _logger.LogWarning(
                    "TARGET_EMAIL is missing. Email skipped for UserEventId: {UserEventId}",
                    userEvent.Id);
            }
            else
            {
                _logger.LogInformation(
                    "Attempting to send ticket email for UserEventId: {UserEventId}",
                    userEvent.Id);

                await _emailService.SendEmail(targetEmail, ev.UrlOfEvent, userEvent.Id, email);

                _logger.LogInformation(
                    "Ticket email sent for UserEventId: {UserEventId}",
                    userEvent.Id);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send ticket email for UserEventId: {UserEventId}", userEvent.Id);
        }

        _logger.LogInformation(
            "Ticket issuing process completed. UserEventId: {UserEventId}, UserId: {UserId}, EventId: {EventId}",
            userEvent.Id, userEvent.UserId, userEvent.EventId);
    }
}