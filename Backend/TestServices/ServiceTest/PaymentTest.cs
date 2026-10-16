using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Interfaces;
using EventApp.Services.Model;
using EventApp.Services.Services;
using EventApp.Services.Services.Interfaces;
using EventApp.Services.Services.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using Stripe.Checkout;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TestServices.ServiceTest;

[TestFixture]
public class PaymentTest
{
    private Mock<ILogger<PaymentService>> _loggerMock = null!;
    private ApplicationDbContext _context = null!;
    private Mock<IQrCodeService> _qrMock = null!;
    private Mock<ISmsService> _smsMock = null!;
    private Mock<IEmailService> _emailMock = null!;
    private Mock<IPdfService> _pdfMock = null!;
    private Mock<UserManager<ApplicationUser>> _userManagerMock = null!;
    private PaymentService _service = null!;

    private string? _originalStripeKey;
    private string? _originalSmsState;
    private string? _originalTargetEmail;

    [SetUp]
    public void SetUp()
    {
        _originalStripeKey = Environment.GetEnvironmentVariable("STRIP_SEC_KEY");
        _originalSmsState = Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE");
        _originalTargetEmail = Environment.GetEnvironmentVariable("TARGET_EMAIL");

        _loggerMock = new Mock<ILogger<PaymentService>>();
        _qrMock = new Mock<IQrCodeService>();
        _smsMock = new Mock<ISmsService>();
        _emailMock = new Mock<IEmailService>();
        _pdfMock = new Mock<IPdfService>();

        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _context = new ApplicationDbContext(options);

        _service = new PaymentService(
            _loggerMock.Object,
            _context,
            _qrMock.Object,
            _smsMock.Object,
            _emailMock.Object,
            _userManagerMock.Object,
            _pdfMock.Object);
    }

    [TearDown]
    public void TearDown()
    {
        Environment.SetEnvironmentVariable("STRIP_SEC_KEY", _originalStripeKey);
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", _originalSmsState);
        Environment.SetEnvironmentVariable("TARGET_EMAIL", _originalTargetEmail);
        _context.Dispose();
    }

    // ============================================================
    // Helpers
    // ============================================================

    private async Task<Event> SeedEventAsync(
        int id = 1,
        string name = "Test Event",
        string? url = "https://example.com/event")
    {
        var ev = new Event
        {
            Id = id,
            NameOfEvent = name,
            UrlOfEvent = url,
            StartOfEvent = DateTime.UtcNow.AddDays(10),
            Address = "ul. Test 1",
            TypeOfEvent = "music",
            ExternalEventId = $"ext-{id}"
        };
        _context.Events.Add(ev);
        await _context.SaveChangesAsync();
        return ev;
    }

    private async Task<UserEvent> SeedUserEventAsync(
        string userId,
        int eventId,
        StatesOfTicket paymentState,
        TicketState ticketState = TicketState.NotIssued,
        string? paymentId = null)
    {
        var ue = new UserEvent
        {
            UserId = userId,
            EventId = eventId,
            CreatedAt = DateTime.UtcNow,
            PaymentState = paymentState,
            PaymentStateAt = DateTime.UtcNow,
            TicketState = ticketState,
            PaymentId = paymentId
        };
        _context.UserEvents.Add(ue);
        await _context.SaveChangesAsync();
        return ue;
    }

    private static Session CreateSession(
        string id = "cs_test_123",
        string paymentStatus = "paid",
        Dictionary<string, string>? metadata = null)
    {
        return new Session
        {
            Id = id,
            PaymentStatus = paymentStatus,
            Metadata = metadata ?? new Dictionary<string, string>()
        };
    }

    // ============================================================
    // BuyTicketAsync – ścieżki BEZ wywołania Stripe
    // ============================================================

    [Test]
    public async Task BuyTicketAsync_WhenStripeKeyMissing_ReturnsError()
    {
        Environment.SetEnvironmentVariable("STRIP_SEC_KEY", null);

        var result = await _service.BuyTicketAsync("user-1", 1);

        Assert.That(result.EventNotFound, Is.False);
        Assert.That(result.AlreadyBoughtTicket, Is.False);
        Assert.That(result.PaymentAlreadyPending, Is.False);
        Assert.That(result.Errors, Is.Not.Null);
        Assert.That(result.Errors!.Any(e => e.Code == "MissingStripeKey"), Is.True);
        Assert.That(result.Response, Is.Null);
    }

    [Test]
    public async Task BuyTicketAsync_WhenStripeKeyWhitespace_ReturnsError()
    {
        Environment.SetEnvironmentVariable("STRIP_SEC_KEY", "   ");

        var result = await _service.BuyTicketAsync("user-1", 1);

        Assert.That(result.Errors!.Any(e => e.Code == "MissingStripeKey"), Is.True);
    }

    [Test]
    public async Task BuyTicketAsync_WhenEventNotFound_ReturnsEventNotFound()
    {
        Environment.SetEnvironmentVariable("STRIP_SEC_KEY", "sk_test_xxx");

        var result = await _service.BuyTicketAsync("user-1", 999);

        Assert.That(result.EventNotFound, Is.True);
        Assert.That(result.Response, Is.Null);
    }

    [Test]
    public async Task BuyTicketAsync_WhenAlreadyPaid_ReturnsAlreadyBought()
    {
        Environment.SetEnvironmentVariable("STRIP_SEC_KEY", "sk_test_xxx");
        var ev = await SeedEventAsync(10);
        await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Paid, TicketState.Active);

        var result = await _service.BuyTicketAsync("user-1", ev.Id!.Value);

        Assert.That(result.AlreadyBoughtTicket, Is.True);
        Assert.That(result.Response, Is.Null);
    }

    [Test]
    public async Task BuyTicketAsync_WhenPendingExists_ReturnsPaymentAlreadyPending()
    {
        Environment.SetEnvironmentVariable("STRIP_SEC_KEY", "sk_test_xxx");
        var ev = await SeedEventAsync(20);
        var pending = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending);

        var result = await _service.BuyTicketAsync("user-1", ev.Id!.Value);

        Assert.That(result.PaymentAlreadyPending, Is.True);
        Assert.That(result.UserEventId, Is.EqualTo(pending.Id));
        Assert.That(result.Response, Is.Null);
    }

    // Uwaga: pełny sukces BuyTicketAsync (Stripe Session) wymaga
    // refaktoryzacji (IStripeSessionService) albo testu integracyjnego.

    // ============================================================
    // CancelPendingPaymentAsync
    // ============================================================

    [Test]
    public async Task CancelPendingPaymentAsync_WhenPendingExists_CancelsAndReturnsTrue()
    {
        var ev = await SeedEventAsync(30);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending);

        var result = await _service.CancelPendingPaymentAsync("user-1", ue.Id);

        Assert.That(result, Is.True);

        var updated = await _context.UserEvents.FindAsync(ue.Id);

        Assert.That(updated, Is.Not.Null);
        Assert.That(
            updated!.PaymentState,
            Is.EqualTo(StatesOfTicket.Cancelled));
    }

    [Test]
    public async Task CancelPendingPaymentAsync_WhenNotFound_ReturnsFalse()
    {
        var result = await _service.CancelPendingPaymentAsync("user-1", 999);
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task CancelPendingPaymentAsync_WhenWrongUser_ReturnsFalse()
    {
        var ev = await SeedEventAsync(31);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending);

        var result = await _service.CancelPendingPaymentAsync("other-user", ue.Id);

        Assert.That(result, Is.False);
        var updated = await _context.UserEvents.FindAsync(ue.Id);
        Assert.That(updated!.PaymentState, Is.EqualTo(StatesOfTicket.Pending));
    }

    [Test]
    public async Task CancelPendingPaymentAsync_WhenAlreadyPaid_ReturnsFalse()
    {
        var ev = await SeedEventAsync(32);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Paid, TicketState.Active);

        var result = await _service.CancelPendingPaymentAsync("user-1", ue.Id);

        Assert.That(result, Is.False);
        Assert.That((await _context.UserEvents.FindAsync(ue.Id))!.PaymentState,
            Is.EqualTo(StatesOfTicket.Paid));
    }

    // ============================================================
    // HandleExpiredPaymentAsync
    // ============================================================

    [Test]
    public async Task HandleExpiredPaymentAsync_WhenSessionNull_DoesNothing()
    {
        await _service.HandleExpiredPaymentAsync(null!);
        Assert.That(await _context.UserEvents.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task HandleExpiredPaymentAsync_WhenSessionIdEmpty_DoesNothing()
    {
        await _service.HandleExpiredPaymentAsync(new Session { Id = "" });
        Assert.That(await _context.UserEvents.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task HandleExpiredPaymentAsync_WhenUserEventNotFound_DoesNothing()
    {
        await _service.HandleExpiredPaymentAsync(CreateSession("cs_unknown"));
        Assert.That(await _context.UserEvents.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task HandleExpiredPaymentAsync_WhenPending_SetsExpired()
    {
        var ev = await SeedEventAsync(40);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: "cs_exp_1");

        await _service.HandleExpiredPaymentAsync(CreateSession("cs_exp_1"));

        var updated = await _context.UserEvents.FindAsync(ue.Id);
        Assert.That(updated!.PaymentState, Is.EqualTo(StatesOfTicket.Expired));
    }

    [Test]
    public async Task HandleExpiredPaymentAsync_WhenNotPending_Ignores()
    {
        var ev = await SeedEventAsync(41);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Paid, TicketState.Active, "cs_exp_2");

        await _service.HandleExpiredPaymentAsync(CreateSession("cs_exp_2"));

        Assert.That((await _context.UserEvents.FindAsync(ue.Id))!.PaymentState,
            Is.EqualTo(StatesOfTicket.Paid));
    }

    // ============================================================
    // HandleRefundedPaymentAsync
    // ============================================================

    [Test]
    public async Task HandleRefundedPaymentAsync_WhenSessionIdEmpty_DoesNothing()
    {
        await _service.HandleRefundedPaymentAsync("");
        await _service.HandleRefundedPaymentAsync(null!);
        Assert.That(await _context.UserEvents.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task HandleRefundedPaymentAsync_WhenUserEventNotFound_DoesNothing()
    {
        await _service.HandleRefundedPaymentAsync("cs_missing");
        Assert.That(await _context.UserEvents.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task HandleRefundedPaymentAsync_WhenPaid_SetsRefundedAndCancelsTicket()
    {
        var ev = await SeedEventAsync(50);
        var ue = await SeedUserEventAsync(
            "user-1", ev.Id!.Value, StatesOfTicket.Paid, TicketState.Active, "cs_ref_1");

        await _service.HandleRefundedPaymentAsync("cs_ref_1");

        var updated = await _context.UserEvents.FindAsync(ue.Id);
        Assert.That(updated!.PaymentState, Is.EqualTo(StatesOfTicket.Refunded));
        Assert.That(updated.TicketState, Is.EqualTo(TicketState.Cancelled));
    }

    [Test]
    public async Task HandleRefundedPaymentAsync_WhenAlreadyRefunded_IsIdempotent()
    {
        var ev = await SeedEventAsync(51);
        var ue = await SeedUserEventAsync(
            "user-1", ev.Id!.Value, StatesOfTicket.Refunded, TicketState.Cancelled, "cs_ref_2");
        var originalAt = ue.PaymentStateAt;

        await _service.HandleRefundedPaymentAsync("cs_ref_2");

        var updated = await _context.UserEvents.FindAsync(ue.Id);
        Assert.That(updated!.PaymentState, Is.EqualTo(StatesOfTicket.Refunded));
        Assert.That(updated.PaymentStateAt, Is.EqualTo(originalAt)); // nie nadpisuje
    }

    // ============================================================
    // HandleSuccessfulPaymentAsync
    // ============================================================

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenSessionNull_DoesNothing()
    {
        await _service.HandleSuccessfulPaymentAsync(null!);
        Assert.That(await _context.UserEvents.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenNotPaid_DoesNothing()
    {
        var ev = await SeedEventAsync(60);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: "cs_unpaid");

        await _service.HandleSuccessfulPaymentAsync(CreateSession("cs_unpaid", paymentStatus: "unpaid"));

        Assert.That((await _context.UserEvents.FindAsync(ue.Id))!.PaymentState,
            Is.EqualTo(StatesOfTicket.Pending));
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenUserEventNotFound_DoesNothing()
    {
        await _service.HandleSuccessfulPaymentAsync(CreateSession("cs_ghost", "paid"));
        Assert.That(await _context.UserEvents.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenAlreadyPaid_IsIdempotent()
    {
        var ev = await SeedEventAsync(61);
        var ue = await SeedUserEventAsync(
            "user-1", ev.Id!.Value, StatesOfTicket.Paid, TicketState.Active, "cs_paid_1");

        await _service.HandleSuccessfulPaymentAsync(CreateSession("cs_paid_1", "paid"));

        // Nie woła QR / PDF / Email
        _qrMock.Verify(x => x.GenerateQrCode(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>()), Times.Never);
        _pdfMock.Verify(x => x.GeneratePdfAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<byte[]>()), Times.Never);
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenNotPending_Ignores()
    {
        var ev = await SeedEventAsync(62);
        var ue = await SeedUserEventAsync(
            "user-1", ev.Id!.Value, StatesOfTicket.Cancelled, paymentId: "cs_cancelled");

        await _service.HandleSuccessfulPaymentAsync(CreateSession("cs_cancelled", "paid"));

        Assert.That((await _context.UserEvents.FindAsync(ue.Id))!.PaymentState,
            Is.EqualTo(StatesOfTicket.Cancelled));
        _qrMock.Verify(x => x.GenerateQrCode(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenUserIdMismatch_DoesNotMarkPaid()
    {
        var ev = await SeedEventAsync(63);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: "cs_mismatch");

        var session = CreateSession("cs_mismatch", "paid", new Dictionary<string, string>
        {
            ["UserId"] = "hacker-user",
            ["EventId"] = ev.Id.ToString(),
            ["UserEventId"] = ue.Id.ToString()
        });

        await _service.HandleSuccessfulPaymentAsync(session);

        Assert.That((await _context.UserEvents.FindAsync(ue.Id))!.PaymentState,
            Is.EqualTo(StatesOfTicket.Pending));
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenEventIdMismatch_DoesNotMarkPaid()
    {
        var ev = await SeedEventAsync(64);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: "cs_ev_mismatch");

        var session = CreateSession("cs_ev_mismatch", "paid", new Dictionary<string, string>
        {
            ["UserId"] = "user-1",
            ["EventId"] = "99999",
            ["UserEventId"] = ue.Id.ToString()
        });

        await _service.HandleSuccessfulPaymentAsync(session);

        Assert.That((await _context.UserEvents.FindAsync(ue.Id))!.PaymentState,
            Is.EqualTo(StatesOfTicket.Pending));
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenPendingAndPaid_MarksPaidAndIssuesTicket()
    {
        var ev = await SeedEventAsync(70, "Koncert", "https://event.example/70");
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: "cs_ok");

        var user = new ApplicationUser
        {
            Id = "user-1",
            Email = "buyer@example.com",
            UserName = "buyer@example.com"
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync("user-1"))
            .ReturnsAsync(user);

        var qrBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47 };
        _qrMock
            .Setup(x => x.GenerateQrCode(ev.UrlOfEvent!, ue.Id, user.Email!))
            .Returns(qrBytes);

        _pdfMock
            .Setup(x => x.GeneratePdfAsync(
                ev.NameOfEvent!,
                It.IsAny<string>(),
                ev.Address,
                ev.TypeOfEvent,
                ev.UrlOfEvent,
                user.Email!,
                ue.Id,
                qrBytes))
            .Returns(Task.CompletedTask);

        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "false");
        Environment.SetEnvironmentVariable("TARGET_EMAIL", "tickets@example.com");

        _emailMock
            .Setup(x => x.SendEmail("tickets@example.com", ev.UrlOfEvent!, ue.Id, user.Email!))
            .Returns(Task.CompletedTask);

        var session = CreateSession("cs_ok", "paid", new Dictionary<string, string>
        {
            ["UserId"] = "user-1",
            ["EventId"] = ev.Id.ToString(),
            ["UserEventId"] = ue.Id.ToString()
        });

        await _service.HandleSuccessfulPaymentAsync(session);

        var updated = await _context.UserEvents.FindAsync(ue.Id);
        Assert.That(updated!.PaymentState, Is.EqualTo(StatesOfTicket.Paid));
        Assert.That(updated.TicketState, Is.EqualTo(TicketState.Active));

        _qrMock.Verify(x => x.GenerateQrCode(ev.UrlOfEvent!, ue.Id, user.Email!), Times.Once);
        _pdfMock.Verify(x => x.GeneratePdfAsync(
            ev.NameOfEvent!, It.IsAny<string>(), ev.Address, ev.TypeOfEvent,
            ev.UrlOfEvent, user.Email!, ue.Id, qrBytes), Times.Once);
        _emailMock.Verify(x => x.SendEmail(
            "tickets@example.com", ev.UrlOfEvent!, ue.Id, user.Email!), Times.Once);
        _smsMock.Verify(x => x.SendSMS(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_FindsUserEventByMetadataFallback()
    {
        var ev = await SeedEventAsync(71);
        // PaymentId jeszcze nie ustawione / inne
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: null);

        var user = new ApplicationUser { Id = "user-1", Email = "a@b.com", UserName = "a@b.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _qrMock.Setup(x => x.GenerateQrCode(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>()))
            .Returns(new byte[] { 1, 2, 3 });
        _pdfMock.Setup(x => x.GeneratePdfAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<byte[]>()))
            .Returns(Task.CompletedTask);

        Environment.SetEnvironmentVariable("TARGET_EMAIL", null);
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "false");

        var session = CreateSession("cs_fallback", "paid", new Dictionary<string, string>
        {
            ["UserEventId"] = ue.Id.ToString(),
            ["UserId"] = "user-1",
            ["EventId"] = ev.Id.ToString()
        });

        await _service.HandleSuccessfulPaymentAsync(session);

        var updated = await _context.UserEvents.FindAsync(ue.Id);
        Assert.That(updated!.PaymentState, Is.EqualTo(StatesOfTicket.Paid));
        Assert.That(updated.TicketState, Is.EqualTo(TicketState.Active));
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenSmsEnabled_SendsSms()
    {
        var ev = await SeedEventAsync(72, url: "https://event.example/72");
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: "cs_sms");

        var user = new ApplicationUser { Id = "user-1", Email = "sms@test.com", UserName = "sms@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _qrMock.Setup(x => x.GenerateQrCode(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>()))
            .Returns(new byte[] { 1 });
        _pdfMock.Setup(x => x.GeneratePdfAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<byte[]>()))
            .Returns(Task.CompletedTask);

        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "true");
        Environment.SetEnvironmentVariable("TARGET_EMAIL", null);

        var session = CreateSession("cs_sms", "paid", new Dictionary<string, string>
        {
            ["UserId"] = "user-1",
            ["EventId"] = ev.Id.ToString()
        });

        await _service.HandleSuccessfulPaymentAsync(session);

        _smsMock.Verify(x => x.SendSMS("https://event.example/72"), Times.Once);
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenQrFails_DoesNotCallPdfOrEmail()
    {
        var ev = await SeedEventAsync(73);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: "cs_qr_fail");

        var user = new ApplicationUser { Id = "user-1", Email = "q@test.com", UserName = "q@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);

        _qrMock
            .Setup(x => x.GenerateQrCode(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>()))
            .Throws(new Exception("QR broken"));

        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "false");
        Environment.SetEnvironmentVariable("TARGET_EMAIL", "t@test.com");

        var session = CreateSession("cs_qr_fail", "paid", new Dictionary<string, string>
        {
            ["UserId"] = "user-1",
            ["EventId"] = ev.Id.ToString()
        });

        await _service.HandleSuccessfulPaymentAsync(session);

        // Płatność i tak oznaczona jako Paid
        var updated = await _context.UserEvents.FindAsync(ue.Id);
        Assert.That(updated!.PaymentState, Is.EqualTo(StatesOfTicket.Paid));
        Assert.That(updated.TicketState, Is.EqualTo(TicketState.Active));

        _pdfMock.Verify(x => x.GeneratePdfAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<byte[]>()), Times.Never);
        _emailMock.Verify(x => x.SendEmail(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task HandleSuccessfulPaymentAsync_WhenEmailServiceThrows_StillMarksPaid()
    {
        var ev = await SeedEventAsync(74);
        var ue = await SeedUserEventAsync("user-1", ev.Id!.Value, StatesOfTicket.Pending, paymentId: "cs_mail_fail");

        var user = new ApplicationUser { Id = "user-1", Email = "m@test.com", UserName = "m@test.com" };
        _userManagerMock.Setup(x => x.FindByIdAsync("user-1")).ReturnsAsync(user);
        _qrMock.Setup(x => x.GenerateQrCode(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>()))
            .Returns(new byte[] { 1 });
        _pdfMock.Setup(x => x.GeneratePdfAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<byte[]>()))
            .Returns(Task.CompletedTask);

        Environment.SetEnvironmentVariable("TARGET_EMAIL", "out@test.com");
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "false");

        _emailMock
            .Setup(x => x.SendEmail(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>()))
            .ThrowsAsync(new Exception("SMTP down"));

        var session = CreateSession("cs_mail_fail", "paid", new Dictionary<string, string>
        {
            ["UserId"] = "user-1",
            ["EventId"] = ev.Id.ToString()
        });

        Assert.DoesNotThrowAsync(async () => await _service.HandleSuccessfulPaymentAsync(session));

        var updated = await _context.UserEvents.FindAsync(ue.Id);
        Assert.That(updated!.PaymentState, Is.EqualTo(StatesOfTicket.Paid));
    }
}