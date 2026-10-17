using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Dto.RelBookmark;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Model;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TestServices.Helper;
using Microsoft.EntityFrameworkCore;

namespace TestServices.IntegrationTest;

[TestFixture]
public class AdminControllerIntergrationTests
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
    // POST /api/v1/admin/admin-seed-database
    // ─────────────────────────────────────────────

    [Test]
    public async Task SeedDatabase_Unauthorized_Returns401()
    {
        // brak tokenu
        var response = await _client.PostAsync("/api/v1/admin/admin-seed-database", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task SeedDatabase_AsUser_Returns403()
    {
        _helper.AuthenticateAs("user", "user-1");

        var response = await _client.PostAsync("/api/v1/admin/admin-seed-database", null);

        // [Authorize(Roles = "admin")] → 403
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task SeedDatabase_EmptyDb_Returns201()
    {
        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync("/api/v1/admin/admin-seed-database", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        var content = await response.Content.ReadAsStringAsync();
        // AnyAsync() == false → body = false
        Assert.That(bool.Parse(content), Is.False);
    }

    [Test]
    public async Task SeedDatabase_DbHasEvents_Returns201True()
    {
        var ev = _helper.CreateEvent(1, "Existing");
        await _factory.SeedAsync(ev);

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync("/api/v1/admin/admin-seed-database", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        var content = await response.Content.ReadAsStringAsync();
        Assert.That(bool.Parse(content), Is.True);
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/admin/admin-app-usage-info
    // ─────────────────────────────────────────────

    [Test]
    public async Task GetAppUsageInfo_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/admin/admin-app-usage-info");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task GetAppUsageInfo_ReturnsCounts()
    {
        var active = await _factory.CreateTestUserAsync(email: "a@test.com", role: "user");
        // ustaw IsActive jeśli CreateTestUserAsync tego nie robi
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(active.Id);
            if (u != null)
            {
                u.IsActive = true;
                await db.SaveChangesAsync();
            }
        }

        var futureEvent = _helper.CreateEvent(1, "Future", start: DateTime.UtcNow.AddDays(5));
        var pastEvent = _helper.CreateEvent(2, "Past", start: DateTime.UtcNow.AddDays(-5));
        var ticket = _helper.CreateUserEvent(1, active.Id, futureEvent.Id!.Value);

        await _factory.SeedAsync(futureEvent, pastEvent, ticket);

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.GetAsync("/api/v1/admin/admin-app-usage-info");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var dto = JsonSerializer.Deserialize<getAppUsageInfoDto>(content, JsonOptions);

        Assert.That(dto, Is.Not.Null);
        Assert.That(dto!.activeUserCount, Is.GreaterThanOrEqualTo(1));
        Assert.That(dto.boughtTickets, Is.EqualTo(1));
        Assert.That(dto.activeTickets, Is.EqualTo(1));
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/admin/admin-events
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminGetEvents_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/admin/admin-events");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminGetEvents_ReturnsEvents()
    {
        await _factory.SeedAsync(_helper.CreateEvent(1, "Concert"));

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.GetAsync("/api/v1/admin/admin-events");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var events = JsonSerializer.Deserialize<getEventAdminDto[]>(content, JsonOptions);

        Assert.That(events, Is.Not.Null);
        Assert.That(events!.Length, Is.EqualTo(1));
        Assert.That(events[0].nameOfEvent, Is.EqualTo("Concert"));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/admin/admin-delete-event/{id}
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminDeleteEvents_Unauthorized_Returns401()
    {
        var response = await _client.PostAsync("/api/v1/admin/admin-delete-event/1", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminDeleteEvents_NotFound_Returns404()
    {
        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync("/api/v1/admin/admin-delete-event/999", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task AdminDeleteEvents_Existing_Returns200()
    {
        var ev = _helper.CreateEvent(5, "To Delete");
        await _factory.SeedAsync(ev);

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync("/api/v1/admin/admin-delete-event/5", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.That(await db.Events.AnyAsync(e => e.Id == 5), Is.False);
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/admin/admin-users
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminGetUsers_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/admin/admin-users");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminGetUsers_ReturnsActiveUsers()
    {
        var user = await _factory.CreateTestUserAsync(email: "user@test.com", role: "user");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(user.Id);
            if (u != null)
            {
                u.IsActive = true;
                await db.SaveChangesAsync();
            }
        }

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.GetAsync("/api/v1/admin/admin-users");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var list = JsonSerializer.Deserialize<List<getAdminUserDto>>(content, JsonOptions);

        Assert.That(list, Is.Not.Null);
        Assert.That(list!.Count, Is.GreaterThanOrEqualTo(1));
        Assert.That(list.Exists(u => u.email == "user@test.com"), Is.True);
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/admin/admin-delete-user/{userId}
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminDeleteUser_NotFound_Returns404()
    {
        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync("/api/v1/admin/admin-delete-user/missing-id", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task AdminDeleteUser_Existing_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(email: "del@test.com", role: "user");

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync($"/api/v1/admin/admin-delete-user/{user.Id}", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/admin/admin-block-user/{userId}
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminBlockUser_NotFound_Returns404()
    {
        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync("/api/v1/admin/admin-block-user/missing", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task AdminBlockUser_AlreadyBlocked_Returns400()
    {
        var user = await _factory.CreateTestUserAsync(email: "blocked@test.com", role: "user");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(user.Id);
            u!.IsActive = false;
            await db.SaveChangesAsync();
        }

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync($"/api/v1/admin/admin-block-user/{user.Id}", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task AdminBlockUser_ActiveUser_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(email: "active@test.com", role: "user");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(user.Id);
            u!.IsActive = true;
            await db.SaveChangesAsync();
        }

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync($"/api/v1/admin/admin-block-user/{user.Id}", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(user.Id);
            Assert.That(u!.IsActive, Is.False);
        }
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/admin/admin-blocked-users
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminGetBlockedUsers_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/admin/admin-blocked-users");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminGetBlockedUsers_ReturnsOnlyInactive()
    {
        var user = await _factory.CreateTestUserAsync(email: "blocked2@test.com", role: "user");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(user.Id);
            u!.IsActive = false;
            await db.SaveChangesAsync();
        }

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.GetAsync("/api/v1/admin/admin-blocked-users");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var list = JsonSerializer.Deserialize<List<getAdminUserDto>>(content, JsonOptions);

        Assert.That(list, Is.Not.Null);
        Assert.That(list!.Exists(u => u.email == "blocked2@test.com"), Is.True);
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/admin/admin-unblock-user/{userId}
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminUnblockUser_NotFound_Returns404()
    {
        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync("/api/v1/admin/admin-unblock-user/missing", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task AdminUnblockUser_AlreadyActive_Returns400()
    {
        var user = await _factory.CreateTestUserAsync(email: "already@test.com", role: "user");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(user.Id);
            u!.IsActive = true;
            await db.SaveChangesAsync();
        }

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync($"/api/v1/admin/admin-unblock-user/{user.Id}", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task AdminUnblockUser_BlockedUser_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(email: "to-unblock@test.com", role: "user");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(user.Id);
            u!.IsActive = false;
            await db.SaveChangesAsync();
        }

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.PostAsync($"/api/v1/admin/admin-unblock-user/{user.Id}", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var u = await db.Users.FindAsync(user.Id);
            Assert.That(u!.IsActive, Is.True);
        }
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/admin/admin-bought-tickets
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminBoughtTickets_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/admin/admin-bought-tickets");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminBoughtTickets_ReturnsTickets()
    {
        var user = await _factory.CreateTestUserAsync(email: "buyer@test.com", role: "user");
        var ev = _helper.CreateEvent(1, "Ticket Event");
        var ticket = _helper.CreateUserEvent(10, user.Id, ev.Id!.Value);
        ticket.PaymentState = StatesOfTicket.Paid;
        ticket.CreatedAt = DateTime.UtcNow;

        await _factory.SeedAsync(ev, ticket);

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.GetAsync("/api/v1/admin/admin-bought-tickets");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var tickets = JsonSerializer.Deserialize<List<getBoughtTicketDto>>(content, JsonOptions);

        Assert.That(tickets, Is.Not.Null);
        Assert.That(tickets!.Count, Is.EqualTo(1));
        Assert.That(tickets[0].eventName, Is.EqualTo("Ticket Event"));
        Assert.That(tickets[0].userEmail, Is.EqualTo("buyer@test.com"));
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/admin/admin-all-bookmarks
    // ─────────────────────────────────────────────

    [Test]
    public async Task AdminGetAllBookmark_Unauthorized_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/admin/admin-all-bookmarks");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminGetAllBookmark_ReturnsBookmarks()
    {
        var ev = _helper.CreateEvent(1, "Bookmarked");
        var bookmark = _helper.CreateBookmark(1, "u1", ev.Id!.Value);

        await _factory.SeedAsync(ev, bookmark);

        _helper.AuthenticateAs("admin", "admin-1");

        var response = await _client.GetAsync("/api/v1/admin/admin-all-bookmarks");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var bookmarks = JsonSerializer.Deserialize<getBookmarkDto[]>(content, JsonOptions);

        Assert.That(bookmarks, Is.Not.Null);
        Assert.That(bookmarks!.Length, Is.EqualTo(1));
        Assert.That(bookmarks[0].eventName, Is.EqualTo("Bookmarked"));
    }
}