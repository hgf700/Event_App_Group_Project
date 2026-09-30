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
using Superpower.Model;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace EventApp.Services.Services;

public class PaymentService : IPaymentService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthService> _logger;
    private readonly ApplicationDbContext _context;
    private readonly IQrCodeService _qrCodeService;
    private readonly ISmsService _smsservice;
    private readonly IEmailService _emailService;
    private readonly string YOUR_DOMAIN = "http://localhost:4200";
    private readonly int AmountToPay = 1000;

    public PaymentService(UserManager<ApplicationUser> userManager,
        IJwtService jwtService,
        ILogger<AuthService> logger,
        ApplicationDbContext dbContext,
        IQrCodeService qrCodeService,
        ISmsService smsservice,
        IEmailService emailService
        )
    {
        _userManager = userManager;
        _jwtService = jwtService;
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

        var alreadyBought = await _context.UserEvents
            .AnyAsync(x => x.UserId == userId && x.EventId == id);

        if (alreadyBought)
        {
            return new BuyTicketResult
            {
                AlreadyBoughtTicket = true
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

        var options = new SessionCreateOptions
        {
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
                            Name = "Bilet na wydarzenie",
                        },
                    },
                    Quantity = 1,
                },
            },

            Mode = "payment",
            SuccessUrl = $"{YOUR_DOMAIN}/payment-success?id={id}",
            CancelUrl = $"{YOUR_DOMAIN}/payment-failed",
        };

        var service = new SessionService();
        Session session = service.Create(options);

        _logger.LogInformation(
            "Stripe checkout session created. UserId: {UserId}, EventId: {EventId}, SessionId: {SessionId}",
            userId,
            id,
            session.Id);

        return new BuyTicketResult
        {
            Response = session.Url
        };
    }

    public async Task<PaymentResult> PaymentSuccess(string userId, int id)
    {
        var ev = await _context.Events.FindAsync(id);
        if (ev == null)
        {
            return new PaymentResult
            {
                EventNotExists = true
            };
        }

        var alreadyExists = await _context.UserEvents
                .AnyAsync(x => x.UserId == userId && x.EventId == id);

        if (alreadyExists)
        {
            return new PaymentResult
            {
                EventAlreadyExists = true
            };
        }

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

        return new PaymentResult
        {
            Success = true
        };
    }
}
