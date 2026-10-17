using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Dto.RelEvent;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using TestServices.Helper;

namespace TestServices.IntegrationTest;

[TestFixture]
public class UserControllerIntergrationTests
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

        await _factory.ResetDbAsync();
    }

    [TearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/user/edit-user-password
    // ─────────────────────────────────────────────

    [Test]
    public async Task EditUserPassword_Unauthorized_Returns401()
    {
        var dto = new postEditUserPasswordDto
        {
            oldPassword = "OldPassword1!",
            newPassword = "NewPassword1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-password", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task EditUserPassword_EmptyOldPassword_Returns400()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var dto = new postEditUserPasswordDto
        {
            oldPassword = "",
            newPassword = "NewPassword1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-password", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task EditUserPassword_EmptyNewPassword_Returns400()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var dto = new postEditUserPasswordDto
        {
            oldPassword = "OldPassword1!",
            newPassword = ""
        };

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-password", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task EditUserPassword_UserNotFound_Returns404()
    {
        _helper.AuthenticateAs("user", "non-existent-user");

        var dto = new postEditUserPasswordDto
        {
            oldPassword = "OldPassword1!",
            newPassword = "NewPassword1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-password", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task EditUserPassword_IncorrectOldPassword_Returns400()
    {
        var user = await _factory.CreateTestUserAsync(password: "CorrectPassword1!", role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var dto = new postEditUserPasswordDto
        {
            oldPassword = "WrongPassword1!",
            newPassword = "NewPassword1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-password", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task EditUserPassword_ValidData_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(password: "OldPassword1!", role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var dto = new postEditUserPasswordDto
        {
            oldPassword = "OldPassword1!",
            newPassword = "NewPassword1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-password", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/user/edit-user-email
    // ─────────────────────────────────────────────

    [Test]
    public async Task EditUserEmail_Unauthorized_Returns401()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-email", "new@test.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task EditUserEmail_EmptyEmail_Returns400()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-email", "");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task EditUserEmail_UserNotFound_Returns404()
    {
        _helper.AuthenticateAs("user", "non-existent-user");

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-email", "new@test.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task EditUserEmail_ValidEmail_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(email: "old@test.com", role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.PostAsJsonAsync("/api/v1/user/edit-user-email", "new@test.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<authResponseDto>(content, JsonOptions);

        Assert.That(result, Is.Not.Null);
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/user/user-tickets
    // ─────────────────────────────────────────────

    [Test]
    public async Task MyEvents_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/user/user-tickets");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task MyEvents_UserNotFound_Returns404()
    {
        _helper.AuthenticateAs("user", "non-existent-user");

        var response = await _client.GetAsync("/api/v1/user/user-tickets");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task MyEvents_NoTickets_Returns404()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.GetAsync("/api/v1/user/user-tickets");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task MyEvents_WithTickets_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");

        var eventEntity = _helper.CreateEvent(1, name: "Concert Night");
        var userEvent = _helper.CreateUserEvent(1, user.Id, eventEntity.Id!.Value);

        await _factory.SeedAsync(eventEntity, userEvent);

        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.GetAsync("/api/v1/user/user-tickets");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var tickets = JsonSerializer.Deserialize<List<getUserBoughtTicketDto>>(content, JsonOptions);

        Assert.That(tickets, Is.Not.Null);
        Assert.That(tickets!.Count, Is.EqualTo(1));
        Assert.That(tickets[0].eventId, Is.EqualTo(1));
        Assert.That(tickets[0].nameOfEvent, Is.EqualTo("Concert Night"));
        Assert.That(tickets[0].city, Is.EqualTo("Warszawa"));
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/user/ticket-detail-with-qr/{eventId}
    // ─────────────────────────────────────────────

    [Test]
    public async Task TicketDetailsWithQr_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/user/ticket-detail-with-qr/1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task TicketDetailsWithQr_TicketNotFound_Returns404()
    {
        var user = await _factory.CreateTestUserAsync(role: "user");
        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.GetAsync("/api/v1/user/ticket-detail-with-qr/999");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task TicketDetailsWithQr_ExistingTicket_Returns200WithQr()
    {
        var user = await _factory.CreateTestUserAsync(email: "user1@test.com", role: "user");

        var eventEntity = _helper.CreateEvent(1, name: "QR Event");
        var userEvent = _helper.CreateUserEvent(10, user.Id, eventEntity.Id!.Value);

        await _factory.SeedAsync(eventEntity, userEvent);

        _helper.AuthenticateAs("user", user.Id);

        var response = await _client.GetAsync("/api/v1/user/ticket-detail-with-qr/1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var ticket = JsonSerializer.Deserialize<getEventTicketWithQrDto>(content, JsonOptions);

        Assert.That(ticket, Is.Not.Null);
        Assert.That(ticket!.eventId, Is.EqualTo(1));
        Assert.That(ticket.nameOfEvent, Is.EqualTo("QR Event"));
        Assert.That(ticket.userEventId, Is.EqualTo(10));
        Assert.That(ticket.qrCode, Is.Not.Null);
        Assert.That(ticket.qrCode!.Length, Is.GreaterThan(0));
    }
}