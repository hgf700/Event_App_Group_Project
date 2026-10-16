using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
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
public class SeedDbServiceTests
{
    private ApplicationDbContext _context = null!;
    private Mock<IHttpClientFactory> _httpClientFactoryMock = null!;
    private Mock<HttpMessageHandler> _httpHandlerMock = null!;
    private string? _originalApiKey;

    [SetUp]
    public void SetUp()
    {
        _originalApiKey = Environment.GetEnvironmentVariable("TICKETMASTER_API_KEY");

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        _httpHandlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        _httpClientFactoryMock = new Mock<IHttpClientFactory>();

        var httpClient = new HttpClient(_httpHandlerMock.Object)
        {
            BaseAddress = new Uri("https://app.ticketmaster.com/")
        };

        _httpClientFactoryMock
            .Setup(x => x.CreateClient(It.IsAny<string>()))
            .Returns(httpClient);
    }

    [TearDown]
    public void TearDown()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", _originalApiKey);
        _context.Dispose();
    }

    private SeedDbService CreateService()
        => new SeedDbService(_httpClientFactoryMock.Object, _context);

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
            _embedded = new
            {
                events
            }
        };

        return JsonSerializer.Serialize(payload);
    }

    // ============================================================
    // 1. Brak API key
    // ============================================================

    [Test]
    public async Task SeedDatabase_WhenApiKeyMissing_DoesNothing()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", null);

        var service = CreateService();
        await service.SeedDatabase();

        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
        // HTTP nie powinno być w ogóle wywołane
        _httpHandlerMock.Protected().Verify(
            "SendAsync",
            Times.Never(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    [Test]
    public async Task SeedDatabase_WhenApiKeyIsWhitespace_DoesNothing()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "   ");

        var service = CreateService();
        await service.SeedDatabase();

        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
    }

    // ============================================================
    // 2. Błąd API
    // ============================================================

    [Test]
    public async Task SeedDatabase_WhenApiReturnsError_DoesNotSaveEvents()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");
        SetupHttpResponse(HttpStatusCode.Unauthorized, """{"fault":"invalid key"}""");

        var service = CreateService();
        await service.SeedDatabase();

        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task SeedDatabase_WhenApiReturns500_DoesNotSaveEvents()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");
        SetupHttpResponse(HttpStatusCode.InternalServerError, "error");

        var service = CreateService();
        await service.SeedDatabase();

        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
    }

    // ============================================================
    // 3. Pusta odpowiedź / brak wydarzeń
    // ============================================================

    [Test]
    public async Task SeedDatabase_WhenNoEventsInResponse_DoesNotSave()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");
        SetupHttpResponse(HttpStatusCode.OK, """{"_embedded":{"events":[]}}""");

        var service = CreateService();
        await service.SeedDatabase();

        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task SeedDatabase_WhenEmbeddedIsNull_DoesNotSave()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");
        SetupHttpResponse(HttpStatusCode.OK, """{}""");

        var service = CreateService();
        await service.SeedDatabase();

        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
    }

    // ============================================================
    // 4. Sukces – zapis nowych wydarzeń
    // ============================================================

    [Test]
    public async Task SeedDatabase_WithNewEvents_SavesThemToDatabase()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        var json = BuildTicketmasterJson(
            new
            {
                id = "tm-001",
                type = "music",
                name = "Koncert Testowy",
                url = "https://ticketmaster.pl/event/1",
                images = new[] { new { url = "https://img.example.com/1.jpg" } },
                dates = new { start = new { dateTime = "2026-11-01T20:00:00Z" } },
                _embedded = new
                {
                    venues = new[]
                    {
                        new
                        {
                            name = "Stadion Narodowy",
                            address = new { line1 = "ul. Testowa 1" },
                            city = new { name = "Warszawa" },
                            country = new { name = "Poland" }
                        }
                    }
                }
            },
            new
            {
                id = "tm-002",
                type = "sports",
                name = "Mecz Testowy",
                url = "https://ticketmaster.pl/event/2",
                images = new[] { new { url = "https://img.example.com/2.jpg" } },
                dates = new { start = new { dateTime = "2026-12-15T18:00:00Z" } },
                _embedded = new
                {
                    venues = new[]
                    {
                        new
                        {
                            name = "Arena",
                            address = new { line1 = "ul. Sportowa 5" },
                            city = new { name = "Kraków" },
                            country = new { name = "Poland" }
                        }
                    }
                }
            });

        SetupHttpResponse(HttpStatusCode.OK, json);

        var service = CreateService();
        await service.SeedDatabase();

        var events = await _context.Events.ToListAsync();
        Assert.That(events, Has.Count.EqualTo(2));

        var e1 = events.Single(e => e.ExternalEventId == "tm-001");
        Assert.That(e1.NameOfEvent, Is.EqualTo("Koncert Testowy"));
        Assert.That(e1.TypeOfEvent, Is.EqualTo("music"));
        Assert.That(e1.UrlOfEvent, Is.EqualTo("https://ticketmaster.pl/event/1"));
        Assert.That(e1.PhotoUrl, Is.EqualTo("https://img.example.com/1.jpg"));
        Assert.That(e1.Address, Is.EqualTo("ul. Testowa 1"));
        Assert.That(e1.City, Is.EqualTo("Warszawa"));
        Assert.That(e1.Country, Is.EqualTo("Poland"));
        Assert.That(e1.NameOfClub, Is.EqualTo("Stadion Narodowy"));
        Assert.That(e1.StartOfEvent.Value.Year, Is.EqualTo(2026));
        Assert.That(e1.StartOfEvent.Value.Month, Is.EqualTo(11));
    }

    // ============================================================
    // 5. Duplikaty – nie dodaje ponownie
    // ============================================================

    [Test]
    public async Task SeedDatabase_WhenEventAlreadyExists_SkipsIt()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        // Istniejące wydarzenie w bazie
        _context.Events.Add(new Event
        {
            ExternalEventId = "tm-001",
            NameOfEvent = "Już w bazie",
            StartOfEvent = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        var json = BuildTicketmasterJson(
            new
            {
                id = "tm-001",
                type = "music",
                name = "Koncert z API",
                url = "https://ticketmaster.pl/event/1",
                images = Array.Empty<object>(),
                dates = new { start = new { dateTime = "2026-11-01T20:00:00Z" } },
                _embedded = new { venues = Array.Empty<object>() }
            },
            new
            {
                id = "tm-003",
                type = "arts",
                name = "Nowe wydarzenie",
                url = "https://ticketmaster.pl/event/3",
                images = Array.Empty<object>(),
                dates = new { start = new { dateTime = "2026-11-10T19:00:00Z" } },
                _embedded = new { venues = Array.Empty<object>() }
            });

        SetupHttpResponse(HttpStatusCode.OK, json);

        var service = CreateService();
        await service.SeedDatabase();

        var events = await _context.Events.ToListAsync();
        Assert.That(events, Has.Count.EqualTo(2)); // 1 stary + 1 nowy
        Assert.That(events.Any(e => e.ExternalEventId == "tm-001" && e.NameOfEvent == "Już w bazie"), Is.True);
        Assert.That(events.Any(e => e.ExternalEventId == "tm-003"), Is.True);
    }

    // ============================================================
    // 6. Brak venue / brak daty / brak obrazka
    // ============================================================

    [Test]
    public async Task SeedDatabase_WhenVenueAndDateMissing_UsesDefaults()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        var before = DateTime.UtcNow.AddSeconds(-5);

        var json = BuildTicketmasterJson(
            new
            {
                id = "tm-no-venue",
                type = (string?)null,
                name = "Event bez venue",
                url = (string?)null,
                images = (object[]?)null,
                dates = (object?)null,
                _embedded = (object?)null
            });

        SetupHttpResponse(HttpStatusCode.OK, json);

        var service = CreateService();
        await service.SeedDatabase();

        var ev = await _context.Events.SingleAsync();
        Assert.That(ev.ExternalEventId, Is.EqualTo("tm-no-venue"));
        Assert.That(ev.NameOfEvent, Is.EqualTo("Event bez venue"));
        Assert.That(ev.Address, Is.Null);
        Assert.That(ev.City, Is.Null);
        Assert.That(ev.Country, Is.Null);
        Assert.That(ev.NameOfClub, Is.Null);
        Assert.That(ev.PhotoUrl, Is.Null);
        Assert.That(ev.StartOfEvent, Is.GreaterThanOrEqualTo(before)); // fallback UtcNow
        Assert.That(ev.StartOfEvent, Is.LessThanOrEqualTo(DateTime.UtcNow.AddSeconds(5)));
    }

    [Test]
    public async Task SeedDatabase_WhenDateInvalid_UsesUtcNow()
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
        await service.SeedDatabase();

        var ev = await _context.Events.SingleAsync();
        Assert.That(ev.StartOfEvent, Is.GreaterThanOrEqualTo(before));
        Assert.That(ev.StartOfEvent, Is.LessThanOrEqualTo(DateTime.UtcNow.AddSeconds(5)));
    }

    // ============================================================
    // 7. Wyjątek HTTP nie wywala aplikacji (catch w serwisie)
    // ============================================================

    [Test]
    public async Task SeedDatabase_WhenHttpThrows_DoesNotPropagateException()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "test-key");

        _httpHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("network down"));

        var service = CreateService();

        Assert.DoesNotThrowAsync(async () => await service.SeedDatabase());
        Assert.That(await _context.Events.CountAsync(), Is.EqualTo(0));
    }

    // ============================================================
    // 8. Sprawdzenie wywołania API (URL zawiera apikey i countryCode)
    // ============================================================

    [Test]
    public async Task SeedDatabase_CallsTicketmasterWithExpectedQuery()
    {
        Environment.SetEnvironmentVariable("TICKETMASTER_API_KEY", "my-secret-key");
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
        await service.SeedDatabase();

        Assert.That(captured, Is.Not.Null);
        Assert.That(captured!.RequestUri!.ToString(), Does.Contain("apikey=my-secret-key"));
        Assert.That(captured.RequestUri.ToString(), Does.Contain("countryCode=PL"));
        Assert.That(captured.RequestUri.ToString(), Does.Contain("size=20"));
        Assert.That(captured.RequestUri.ToString(), Does.Contain("discovery/v2/events.json"));
    }
}