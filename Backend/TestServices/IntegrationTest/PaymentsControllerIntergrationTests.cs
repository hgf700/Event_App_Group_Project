using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TestServices.Helper;

namespace TestServices.IntegrationTest;

[TestFixture]
public class PaymentsControllerIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private EventAppFactory _factory = null!;
    private HttpClient _client = null!;
    private CreateDbObjectHelper _helper = null!;

    [SetUp]
    public async Task SetUp()
    {
        _factory = new EventAppFactory();
        _client = _factory.CreateClient();
        _helper = new CreateDbObjectHelper(_client);

        Environment.SetEnvironmentVariable("STRIP_SEC_KEY", "sk_test_dummy_key_for_integration");
        //Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "true");

        await _factory.ResetDbAsync();
    
    }

    [TearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/payments/buy-ticket/{id}
    // ─────────────────────────────────────────────

    [Test]
    public async Task BuyTicket_Unauthorized_Returns401()
    {
        var response = await _client.PostAsync("/api/v1/payments/buy-ticket/1", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task BuyTicket_EventNotFound_Returns404()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.PostAsync("/api/v1/payments/buy-ticket/99999", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task BuyTicket_AlreadyOwnsTicket_Returns409()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");

        var eventEntity = _helper.CreateEvent(1, name: "Sold Out Event");
        // zakładamy, że "AlreadyBought" = UserEvent ze statusem Paid / Completed
        var userEvent = _helper.CreateUserEvent(1, user.Id, eventEntity.Id!.Value);
        userEvent.PaymentState = StatesOfTicket.Paid; 

        await _factory.SeedAsync(eventEntity, userEvent);

        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.PostAsync($"/api/v1/payments/buy-ticket/{eventEntity.Id}", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));

        var body = await response.Content.ReadAsStringAsync();
        Assert.That(body, Does.Contain("already owns").IgnoreCase);
    }

    [Test]
    public async Task BuyTicket_PaymentAlreadyPending_Returns409()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");

        var eventEntity = _helper.CreateEvent(2, name: "Pending Event");
        var userEvent = _helper.CreateUserEvent(2, user.Id, eventEntity.Id!.Value);
        userEvent.PaymentState = StatesOfTicket.Pending; // dostosuj do wartości z serwisu

        await _factory.SeedAsync(eventEntity, userEvent);

        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.PostAsync($"/api/v1/payments/buy-ticket/{eventEntity.Id}", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/payments/status/{id}
    // ─────────────────────────────────────────────

    [Test]
    public async Task GetPaymentStatus_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/payments/status/1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task GetPaymentStatus_NotFound_Returns404()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.GetAsync("/api/v1/payments/status/99999");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task GetPaymentStatus_OtherUsersPayment_Returns404()
    {
        var owner = await _factory.CreateTestUserAsync(email: "owner@test.com", role: "user");
        var other = await _factory.CreateTestUserAsync(email: "other@test.com", role: "user");

        var eventEntity = _helper.CreateEvent(1);
        var userEvent = _helper.CreateUserEvent(10, owner.Id, eventEntity.Id!.Value);
        userEvent.PaymentState = StatesOfTicket.Pending;

        await _factory.SeedAsync(eventEntity, userEvent);

        _helper.AuthenticateAs("user", other.Id);

        var response = await _client.GetAsync($"/api/v1/payments/status/{userEvent.Id}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    //[Test]
    //public async Task GetPaymentStatus_ExistingPayment_Returns200()
    //{
    //    var user = await _factory.CreateTestUserAsync(role: "user");

    //    var eventEntity = _helper.CreateEvent(1, name: "Status Event");
    //    var userEvent = _helper.CreateUserEvent(20, user.Id, eventEntity.Id!.Value);
    //    userEvent.PaymentState = StatesOfTicket.Pending;
    //    userEvent.CreatedAt = DateTime.UtcNow;
    //      userEvent.PaymentStateAt = DateTime.UtcNow;


    //    await _factory.SeedAsync(eventEntity, userEvent);

    //    _helper.AuthenticateAs("user", user.Id);

    //    var response = await _client.GetAsync($"/api/v1/payments/status/{userEvent.Id}");

    //    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

    //    var content = await response.Content.ReadAsStringAsync();
    //    using var doc = JsonDocument.Parse(content);
    //    var root = doc.RootElement;

    //    Assert.That(root.GetProperty("id").GetInt32(), Is.EqualTo(userEvent.Id));
    //    Assert.That(root.GetProperty("state").GetString(), Is.EqualTo("Pending"));
    //    Assert.That(root.TryGetProperty("createdAt", out _), Is.True);
    //    Assert.That(root.TryGetProperty("paidAt", out _), Is.True);
    //}

    [Test]
    public async Task GetPaymentStatus_ExistingPayment_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");

        var eventEntity = _helper.CreateEvent(1, name: "Status Event");
        var userEvent = _helper.CreateUserEvent(20, user.Id, eventEntity.Id!.Value);
        userEvent.PaymentState = StatesOfTicket.Pending;
        userEvent.CreatedAt = DateTime.UtcNow;
        userEvent.PaymentStateAt = DateTime.UtcNow;

        await _factory.SeedAsync(eventEntity, userEvent);

        // Pobierz faktyczne Id z bazy (EF mógł nadpisać identity)
        int actualUserEventId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var saved = await db.UserEvents
                .AsNoTracking()
                .SingleAsync(x => x.UserId == user.Id && x.EventId == eventEntity.Id);

            actualUserEventId = saved.Id;
        }

        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.GetAsync($"/api/v1/payments/status/{actualUserEventId}");

        var content = await response.Content.ReadAsStringAsync();

        // Jak znowu nie będzie 200 – zobaczysz dlaczego
        Assert.That(
            response.StatusCode,
            Is.EqualTo(HttpStatusCode.OK),
            $"Expected 200 but got {(int)response.StatusCode} {response.StatusCode}. Body: {content}");

        using var doc = JsonDocument.Parse(content);
        var root = doc.RootElement;

        Assert.That(root.GetProperty("id").GetInt32(), Is.EqualTo(actualUserEventId));

        // enum może iść jako string "Pending" albo jako liczba
        var stateProp = root.GetProperty("state");
        if (stateProp.ValueKind == JsonValueKind.String)
            Assert.That(stateProp.GetString(), Is.EqualTo(nameof(StatesOfTicket.Pending)));
        else
            Assert.That(stateProp.GetInt32(), Is.EqualTo((int)StatesOfTicket.Pending));

        Assert.That(root.TryGetProperty("createdAt", out _), Is.True);
        Assert.That(root.TryGetProperty("paidAt", out _), Is.True);
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/payments/stripe-webhook
    // ─────────────────────────────────────────────

    [Test]
    public async Task StripeWebhook_MissingSecret_Returns400()
    {
        // STRIPE_WEBHOOK_SECRET nie jest ustawione w factory
        Environment.SetEnvironmentVariable("STRIPE_WEBHOOK_SECRET", null);

        var content = new StringContent("{}", Encoding.UTF8, "application/json");
        content.Headers.Add("Stripe-Signature", "t=123,v1=abc");

        var response = await _client.PostAsync("/api/v1/payments/stripe-webhook", content);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task StripeWebhook_MissingSignature_Returns400()
    {
        Environment.SetEnvironmentVariable("STRIPE_WEBHOOK_SECRET", "whsec_test_secret");

        var content = new StringContent("{}", Encoding.UTF8, "application/json");
        // brak nagłówka Stripe-Signature

        var response = await _client.PostAsync("/api/v1/payments/stripe-webhook", content);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task StripeWebhook_InvalidSignature_Returns400()
    {
        Environment.SetEnvironmentVariable("STRIPE_WEBHOOK_SECRET", "whsec_test_secret");

        var content = new StringContent("{\"type\":\"checkout.session.completed\"}", Encoding.UTF8, "application/json");
        content.Headers.Add("Stripe-Signature", "t=123456,v1=invalidsignature");

        var response = await _client.PostAsync("/api/v1/payments/stripe-webhook", content);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }
}