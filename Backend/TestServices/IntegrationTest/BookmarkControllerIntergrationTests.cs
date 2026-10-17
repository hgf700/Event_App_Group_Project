using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelBookmark;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TestServices.Helper;

namespace TestServices.IntegrationTest;

public class BookmarkControllerIntegrationTests
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
    // GET /api/v1/bookmark/user-bookmarks
    // ─────────────────────────────────────────────

    [Test]
    public async Task GetBookmark_Unauthorized_Returns401()
    {
        // Arrange – brak tokenu

        // Act
        var response = await _client.GetAsync("/api/v1/bookmark/user-bookmarks");

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task GetBookmark_Authorized_NoBookmarks_ReturnsEmptyArray()
    {
        // Arrange
        _helper.AuthenticateAs("user", "user-1");

        // Act
        var response = await _client.GetAsync("/api/v1/bookmark/user-bookmarks");

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var bookmarks = JsonSerializer.Deserialize<getBookmarkDto[]>(content, JsonOptions);

        Assert.That(bookmarks, Is.Not.Null);
        Assert.That(bookmarks!.Length, Is.EqualTo(0));
    }

    [Test]
    public async Task GetBookmark_Authorized_WithBookmarks_ReturnsBookmarks()
    {
        // Arrange
        var eventEntity = _helper.CreateEvent(1, name: "Test Event");
        var bookmark = _helper.CreateBookmark(1, "user-1", eventEntity.Id!.Value);

        await _factory.SeedAsync(eventEntity, bookmark);

        _helper.AuthenticateAs("user", "user-1");

        // Act
        var response = await _client.GetAsync("/api/v1/bookmark/user-bookmarks");

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var bookmarks = JsonSerializer.Deserialize<getBookmarkDto[]>(content, JsonOptions);

        Assert.That(bookmarks, Is.Not.Null);
        Assert.That(bookmarks!.Length, Is.EqualTo(1));
        Assert.That(bookmarks[0].userId, Is.EqualTo("user-1"));
        Assert.That(bookmarks[0].eventId, Is.EqualTo(eventEntity.Id));
        Assert.That(bookmarks[0].eventName, Is.EqualTo("Test Event"));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/bookmark/bookmark-event/{eventId}
    // ─────────────────────────────────────────────

    [Test]
    public async Task BookmarkEvent_Unauthorized_Returns401()
    {
        // Act
        var response = await _client.PostAsync("/api/v1/bookmark/bookmark-event/1", null);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task BookmarkEvent_EventDoesNotExist_Returns404()
    {
        // Arrange
        _helper.AuthenticateAs("user", "user-1");

        // Act
        var response = await _client.PostAsync("/api/v1/bookmark/bookmark-event/99999", null);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task BookmarkEvent_ValidEvent_Returns201Created()
    {
        // Arrange
        var eventEntity = _helper.CreateEvent(1, name: "Concert");
        await _factory.SeedAsync(eventEntity);

        _helper.AuthenticateAs("user", "user-1");

        // Act
        var response = await _client.PostAsync($"/api/v1/bookmark/bookmark-event/{eventEntity.Id}", null);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        // Weryfikacja, że bookmark został zapisany
        var getResponse = await _client.GetAsync("/api/v1/bookmark/user-bookmarks");
        var content = await getResponse.Content.ReadAsStringAsync();
        var bookmarks = JsonSerializer.Deserialize<getBookmarkDto[]>(content, JsonOptions);

        Assert.That(bookmarks, Is.Not.Null);
        Assert.That(bookmarks!.Length, Is.EqualTo(1));
        Assert.That(bookmarks[0].eventId, Is.EqualTo(eventEntity.Id));
        Assert.That(bookmarks[0].eventName, Is.EqualTo("Concert"));
    }

    [Test]
    public async Task BookmarkEvent_AlreadyBookmarked_Returns409Conflict()
    {
        // Arrange
        var eventEntity = _helper.CreateEvent(1, name: "Already Bookmarked");
        var bookmark = _helper.CreateBookmark(1, "user-1", eventEntity.Id!.Value);

        await _factory.SeedAsync(eventEntity, bookmark);

        _helper.AuthenticateAs("user", "user-1");

        // Act
        var response = await _client.PostAsync($"/api/v1/bookmark/bookmark-event/{eventEntity.Id}", null);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/bookmark/unbookmark-event/{eventId}
    // ─────────────────────────────────────────────

    [Test]
    public async Task UnBookmarkEvent_Unauthorized_Returns401()
    {
        // Act
        var response = await _client.PostAsync("/api/v1/bookmark/unbookmark-event/1", null);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task UnBookmarkEvent_BookmarkDoesNotExist_Returns404()
    {
        // Arrange
        _helper.AuthenticateAs("user", "user-1");

        // Act
        var response = await _client.PostAsync("/api/v1/bookmark/unbookmark-event/99999", null);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task UnBookmarkEvent_ExistingBookmark_Returns204NoContent()
    {
        // Arrange
        var eventEntity = _helper.CreateEvent(1, name: "To Unbookmark");
        var bookmark = _helper.CreateBookmark(1, "user-1", eventEntity.Id!.Value);

        await _factory.SeedAsync(eventEntity, bookmark);

        _helper.AuthenticateAs("user", "user-1");

        // Act
        var response = await _client.PostAsync($"/api/v1/bookmark/unbookmark-event/{eventEntity.Id}", null);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));

        // Sprawdzenie, że bookmark został usunięty
        var getResponse = await _client.GetAsync("/api/v1/bookmark/user-bookmarks");
        var content = await getResponse.Content.ReadAsStringAsync();
        var bookmarks = JsonSerializer.Deserialize<getBookmarkDto[]>(content, JsonOptions);

        Assert.That(bookmarks, Is.Not.Null);
        Assert.That(bookmarks!.Length, Is.EqualTo(0));
    }
}