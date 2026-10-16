using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Services;
using Microsoft.EntityFrameworkCore;
using Moq;
using Moq.Protected;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace TestServices.AppServiceTest;

[TestFixture]
public class SearchOrDownloadTest
{
    private ApplicationDbContext _context = null!;
    private Mock<HttpMessageHandler> _httpHandlerMock = null!;
    private HttpClient _httpClient = null!;
    private string? _originalApiKey;

    [SetUp]
    public void SetUp()
    {
        _originalApiKey = Environment.GetEnvironmentVariable("TICKETMASTER_API_KEY");

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        _httpHandlerMock = new Mock<HttpMessageHandler>(MockBehavior.Loose);
        _httpClient = new HttpClient(_httpHandlerMock.Object);
    }

    [TearDown]
    public void TearDown()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", _originalApiKey);
        _httpClient.Dispose();
        _context.Dispose();
    }

    private SendOrDownloadFromApiService CreateService()
        => new SendOrDownloadFromApiService(_httpClient, _context);

    private void SetupHttpResponse(HttpStatusCode statusCode, string jsonBody)
    {
        _httpHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = statusCode,
                Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
            });
    }

    private static string BuildTicketmasterJson(params object[] events)
    {
        var payload = new
        {
            _embedded = new { events }
        };
        return JsonSerializer.Serialize(payload);
    }

    // ============================================================
    // 1. Walidacja city
    // ============================================================

    [Test]
    public void FetchAndSaveEventsAsync_WhenCityIsNull_ThrowsArgumentException()
    {
        var service = CreateService();

        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.FetchAndSaveEventsAsync(null));

        Assert.That(ex!.Message, Does.Contain("City is required"));
    }

    [Test]
    public void FetchAndSaveEventsAsync_WhenCityIsEmpty_ThrowsArgumentException()
    {
        var service = CreateService();

        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.FetchAndSaveEventsAsync(""));

        Assert.That(ex!.Message, Does.Contain("City is required"));
    }

    [Test]
    public void FetchAndSaveEventsAsync_WhenCityIsWhitespace_ThrowsArgumentException()
    {
        var service = CreateService();

        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.FetchAndSaveEventsAsync("   "));

        Assert.That(ex!.Message, Does.Contain("City is required"));
    }

    // ============================================================
    // 2. Brak API key
    // ============================================================

    [Test]
    public void FetchAndSaveEventsAsync_WhenApiKeyMissing_ThrowsInvalidOperationException()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", null);

        var service = CreateService();

        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.FetchAndSaveEventsAsync("Warsaw"));

        Assert.That(ex!.Message, Is.EqualTo("TICKETMASTER_API_KEY is not set."));
    }

    // ============================================================
    // 3. Błąd API → pusta lista
    // ============================================================

    [Test]
    public async Task FetchAndSaveEventsAsync_WhenApiReturnsError_ReturnsEmptyList()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");
        SetupHttpResponse(HttpStatusCode.Unauthorized, """{"fault":"invalid"}""");

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Warsaw");

        Assert.That(result, Is.Empty);
        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task FetchAndSaveEventsAsync_WhenApiReturns500_ReturnsEmptyList()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");
        SetupHttpResponse(HttpStatusCode.InternalServerError, "error");

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Krakow");

        Assert.That(result, Is.Empty);
    }

    // ============================================================
    // 4. Brak wydarzeń w odpowiedzi
    // ============================================================

    [Test]
    public async Task FetchAndSaveEventsAsync_WhenNoEvents_ReturnsEmptyList()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");
        SetupHttpResponse(HttpStatusCode.OK, """{"_embedded":{"events":[]}}""");

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Warsaw");

        Assert.That(result, Is.Empty);
        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task FetchAndSaveEventsAsync_WhenEmbeddedNull_ReturnsEmptyList()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");
        SetupHttpResponse(HttpStatusCode.OK, """{}""");

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Warsaw");

        Assert.That(result, Is.Empty);
    }

    // ============================================================
    // 5. Sukces – zapis i mapowanie na DTO
    // ============================================================

    [Test]
    public async Task FetchAndSaveEventsAsync_WithNewEvents_SavesAndReturnsDtos()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        var json = BuildTicketmasterJson(
            new
            {
                id = "tm-101",
                type = "music",
                name = "Koncert Warszawa",
                url = "https://ticketmaster.pl/e/1",
                images = new[] { new { url = "https://img.example.com/1.jpg" } },
                dates = new { start = new { dateTime = "2026-11-01T20:00:00Z" } },
                _embedded = new
                {
                    venues = new[]
                    {
                        new
                        {
                            name = "Stadion",
                            address = new { line1 = "ul. Test 1" },
                            city = new { name = "Warszawa" },
                            country = new { name = "Poland" }
                        }
                    }
                }
            },
            new
            {
                id = "tm-102",
                type = "sports",
                name = "Mecz",
                url = "https://ticketmaster.pl/e/2",
                images = new[] { new { url = "https://img.example.com/2.jpg" } },
                dates = new { start = new { dateTime = "2026-12-01T18:00:00Z" } },
                _embedded = new
                {
                    venues = new[]
                    {
                        new
                        {
                            name = "Arena",
                            address = new { line1 = "ul. Sport 2" },
                            city = new { name = "Warszawa" },
                            country = new { name = "Poland" }
                        }
                    }
                }
            });

        SetupHttpResponse(HttpStatusCode.OK, json);

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Warsaw");

        Assert.That(result, Has.Count.EqualTo(2));
        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(2));

        var dto1 = result.Single(r => r.nameOfEvent == "Koncert Warszawa");
        Assert.That(dto1.typeOfEvent, Is.EqualTo("music"));
        Assert.That(dto1.urlOfEvent, Is.EqualTo("https://ticketmaster.pl/e/1"));
        Assert.That(dto1.photoUrl, Is.EqualTo("https://img.example.com/1.jpg"));
        Assert.That(dto1.address, Is.EqualTo("ul. Test 1"));
        Assert.That(dto1.city, Is.EqualTo("Warszawa"));
        Assert.That(dto1.country, Is.EqualTo("Poland"));
        Assert.That(dto1.nameOfClub, Is.EqualTo("Stadion"));
        Assert.That(dto1.startOfEvent.Value.Year, Is.EqualTo(2026));
        Assert.That(dto1.eventId, Is.GreaterThan(0)); // Id z bazy po SaveChanges
    }

    // ============================================================
    // 6. Duplikaty – pomija, zwraca tylko nowe
    // ============================================================

    [Test]
    public async Task FetchAndSaveEventsAsync_WhenEventExists_SkipsAndReturnsOnlyNew()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        _context.Events.Add(new Event
        {
            ExternalEventId = "tm-101",
            NameOfEvent = "Już w bazie",
            StartOfEvent = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        var json = BuildTicketmasterJson(
            new
            {
                id = "tm-101",
                type = "music",
                name = "Z API",
                url = "https://x.com/1",
                images = Array.Empty<object>(),
                dates = new { start = new { dateTime = "2026-11-01T20:00:00Z" } },
                _embedded = new { venues = Array.Empty<object>() }
            },
            new
            {
                id = "tm-999",
                type = "arts",
                name = "Nowe wydarzenie",
                url = "https://x.com/999",
                images = Array.Empty<object>(),
                dates = new { start = new { dateTime = "2026-11-10T19:00:00Z" } },
                _embedded = new { venues = Array.Empty<object>() }
            });

        SetupHttpResponse(HttpStatusCode.OK, json);

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Warsaw");

        Assert.That(result, Has.Count.EqualTo(1));
        Assert.That(result[0].nameOfEvent, Is.EqualTo("Nowe wydarzenie"));
        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(2)); // 1 stary + 1 nowy
    }

    [Test]
    public async Task FetchAndSaveEventsAsync_WhenAllEventsExist_ReturnsEmptyList()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        _context.Events.Add(new Event
        {
            ExternalEventId = "tm-only",
            NameOfEvent = "Istniejący",
            StartOfEvent = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        var json = BuildTicketmasterJson(
            new
            {
                id = "tm-only",
                name = "Duplikat",
                dates = new { start = new { dateTime = "2026-01-01T12:00:00Z" } },
                _embedded = new { venues = Array.Empty<object>() }
            });

        SetupHttpResponse(HttpStatusCode.OK, json);

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Warsaw");

        Assert.That(result, Is.Empty);
        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(1));
    }

    // ============================================================
    // 7. Brak venue / daty / obrazka
    // ============================================================

    [Test]
    public async Task FetchAndSaveEventsAsync_WhenVenueAndDateMissing_UsesDefaults()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        var before = DateTime.UtcNow.AddSeconds(-5);

        var json = BuildTicketmasterJson(
            new
            {
                id = "tm-sparse",
                type = (string?)null,
                name = "Minimalny event",
                url = (string?)null,
                images = (object[]?)null,
                dates = (object?)null,
                _embedded = (object?)null
            });

        SetupHttpResponse(HttpStatusCode.OK, json);

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Gdansk");

        Assert.That(result, Has.Count.EqualTo(1));
        var dto = result[0];

        Assert.That(dto.nameOfEvent, Is.EqualTo("Minimalny event"));
        Assert.That(dto.address, Is.Null);
        Assert.That(dto.city, Is.Null);
        Assert.That(dto.country, Is.Null);
        Assert.That(dto.nameOfClub, Is.Null);
        Assert.That(dto.photoUrl, Is.Null);
        Assert.That(dto.startOfEvent, Is.GreaterThanOrEqualTo(before));
        Assert.That(dto.startOfEvent, Is.LessThanOrEqualTo(DateTime.UtcNow.AddSeconds(5)));
    }

    [Test]
    public async Task FetchAndSaveEventsAsync_WhenDateInvalid_UsesUtcNow()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        var before = DateTime.UtcNow.AddSeconds(-5);

        var json = BuildTicketmasterJson(
            new
            {
                id = "tm-bad-date",
                name = "Zła data",
                dates = new { start = new { dateTime = "not-a-date" } },
                _embedded = new { venues = Array.Empty<object>() }
            });

        SetupHttpResponse(HttpStatusCode.OK, json);

        var service = CreateService();
        var result = await service.FetchAndSaveEventsAsync("Lodz");

        Assert.That(result, Has.Count.EqualTo(1));
        Assert.That(result[0].startOfEvent, Is.GreaterThanOrEqualTo(before));
        Assert.That(result[0].startOfEvent, Is.LessThanOrEqualTo(DateTime.UtcNow.AddSeconds(5)));
    }

    // ============================================================
    // 8. Query string – city + apikey
    // ============================================================

    [Test]
    public async Task FetchAndSaveEventsAsync_CallsApiWithCityAndApiKey()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "secret-key-123");
        SetupHttpResponse(HttpStatusCode.OK, """{"_embedded":{"events":[]}}""");

        HttpRequestMessage? captured = null;

        _httpHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => captured = req)
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent("""{"_embedded":{"events":[]}}""", Encoding.UTF8, "application/json")
            });

        var service = CreateService();
        await service.FetchAndSaveEventsAsync("Warsaw");

        Assert.That(captured, Is.Not.Null);
        var uri = captured!.RequestUri!.ToString();

        Assert.That(uri, Does.Contain("apikey=secret-key-123"));
        Assert.That(uri, Does.Contain("city=Warsaw"));
        Assert.That(uri, Does.Contain("size=20"));
        Assert.That(uri, Does.Contain("discovery/v2/events.json"));
    }
}