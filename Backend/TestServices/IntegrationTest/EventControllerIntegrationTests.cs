using EventApp.Domain.Model;
using EventApp.Services.Dto.RelEvent;
using NUnit.Framework;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using TestServices.Helper;

namespace TestServices.IntegrationTest;

[TestFixture]
public class EventControllerIntegrationTests
{
    private EventAppFactory _factory = null!;
    private HttpClient _client = null!;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _factory = new EventAppFactory();
    }

    [SetUp]
    public async Task SetUp()
    {
        _client = _factory.CreateClient();
        await _factory.ResetDbAsync();
    }

    [TearDown]
    public void TearDown()
    {
        _client.Dispose();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _factory.Dispose();
    }

    private static Event CreateEvent(
        int id,
        string name = "Event",
        string? city = "Warszawa",
        DateTime? start = null)
    {
        return new Event
        {
            Id = id,
            ExternalEventId = $"ext-{id}",
            NameOfEvent = name,
            TypeOfEvent = "music",
            UrlOfEvent = $"https://example.com/{id}",
            PhotoUrl = $"https://img.example.com/{id}.jpg",
            StartOfEvent = start ?? DateTime.UtcNow.AddDays(id),
            Address = $"ul. Test {id}",
            City = city,
            Country = "Poland",
            NameOfClub = $"Club {id}"
        };
    }

    private void AuthenticateAs(string role = "user", string userId = "user-1")
    {
        _client.DefaultRequestHeaders.Remove("Authorization");
        _client.DefaultRequestHeaders.Add("Authorization", $"Test {role}|{userId}");
    }

    // ============================================================
    // GET /api/v1/event/public-get-events  (AllowAnonymous)
    // ============================================================

    [Test]
    public async Task PublicGetEvents_WithoutAuth_Returns200AndEmptyList()
    {
        var response = await _client.GetAsync("/api/v1/event/public-get-events");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var body = await response.Content.ReadFromJsonAsync<paginatedResponse<getEventsDto>>(JsonOptions);
        Assert.That(body, Is.Not.Null);
        Assert.That(body!.data, Is.Empty);
        Assert.That(body.totalCount, Is.EqualTo(0));
        Assert.That(body.pageNumber, Is.EqualTo(1));
        Assert.That(body.pageSize, Is.EqualTo(20));
    }

    [Test]
    public async Task PublicGetEvents_WithData_ReturnsPaginatedEvents()
    {
        await _factory.SeedAsync(
            CreateEvent(1, "Koncert A"),
            CreateEvent(2, "Koncert B"),
            CreateEvent(3, "Mecz C"));

        var response = await _client.GetAsync("/api/v1/event/public-get-events?page=1&pageSize=2");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var body = await response.Content.ReadFromJsonAsync<paginatedResponse<getEventsDto>>(JsonOptions);
        Assert.That(body, Is.Not.Null);
        Assert.That(body!.totalCount, Is.EqualTo(3));
        Assert.That(body.pageNumber, Is.EqualTo(1));
        Assert.That(body.pageSize, Is.EqualTo(2));
        Assert.That(body.data, Has.Length.EqualTo(2));

        var first = body.data[0];
        Assert.That(first.eventId, Is.EqualTo(1));
        Assert.That(first.nameOfEvent, Is.EqualTo("Koncert A"));
        Assert.That(first.city, Is.EqualTo("Warszawa"));
        Assert.That(first.country, Is.EqualTo("Poland"));
    }

    [Test]
    public async Task PublicGetEvents_Page2_ReturnsRemainingItems()
    {
        await _factory.SeedAsync(
            CreateEvent(1),
            CreateEvent(2),
            CreateEvent(3));

        var response = await _client.GetAsync("/api/v1/event/public-get-events?page=2&pageSize=2");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var body = await response.Content.ReadFromJsonAsync<paginatedResponse<getEventsDto>>(JsonOptions);
        Assert.That(body!.data, Has.Length.EqualTo(1));
        Assert.That(body.data[0].eventId, Is.EqualTo(3));
        Assert.That(body.totalCount, Is.EqualTo(3));
        Assert.That(body.pageNumber, Is.EqualTo(2));
    }

    [Test]
    public async Task PublicGetEvents_DefaultPagination_UsesPage1Size20()
    {
        var events = Enumerable.Range(1, 25)
            .Select(i => CreateEvent(i, $"Event {i}"))
            .ToArray();
        await _factory.SeedAsync(events);

        var response = await _client.GetAsync("/api/v1/event/public-get-events");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var body = await response.Content.ReadFromJsonAsync<paginatedResponse<getEventsDto>>(JsonOptions);
        Assert.That(body!.pageNumber, Is.EqualTo(1));
        Assert.That(body.pageSize, Is.EqualTo(20));
        Assert.That(body.totalCount, Is.EqualTo(25));
        Assert.That(body.data, Has.Length.EqualTo(20));
    }

    // ============================================================
    // GET /api/v1/event/get-events  (Authorize)
    // ============================================================

    [Test]
    public async Task GetEvents_WithoutAuth_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/event/get-events");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task GetEvents_WithUserAuth_Returns200()
    {
        await _factory.SeedAsync(CreateEvent(1, "Auth Event"));
        AuthenticateAs("user", "user-1");

        var response = await _client.GetAsync("/api/v1/event/get-events");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var body = await response.Content.ReadFromJsonAsync<paginatedResponse<getEventsDto>>(JsonOptions);
        Assert.That(body!.totalCount, Is.EqualTo(1));
        Assert.That(body.data[0].nameOfEvent, Is.EqualTo("Auth Event"));
    }

    [Test]
    public async Task GetEvents_WithAdminAuth_Returns200()
    {
        await _factory.SeedAsync(CreateEvent(1));
        AuthenticateAs("admin", "admin-1");

        var response = await _client.GetAsync("/api/v1/event/get-events?page=1&pageSize=10");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task GetEvents_Pagination_Works()
    {
        await _factory.SeedAsync(
            CreateEvent(1),
            CreateEvent(2),
            CreateEvent(3),
            CreateEvent(4));
        AuthenticateAs();

        var response = await _client.GetAsync("/api/v1/event/get-events?page=2&pageSize=2");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var body = await response.Content.ReadFromJsonAsync<paginatedResponse<getEventsDto>>(JsonOptions);
        Assert.That(body!.data, Has.Length.EqualTo(2));
        Assert.That(body.totalCount, Is.EqualTo(4));
        Assert.That(body.pageNumber, Is.EqualTo(2));
        Assert.That(body.pageSize, Is.EqualTo(2));
    }

    // ============================================================
    // GET /api/v1/event/event-details/{id}  (Authorize)
    // ============================================================

    [Test]
    public async Task EventDetails_WithoutAuth_Returns401()
    {
        var response = await _client.GetAsync("/api/v1/event/event-details/1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task EventDetails_WhenNotFound_Returns404()
    {
        AuthenticateAs();

        var response = await _client.GetAsync("/api/v1/event/event-details/999");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task EventDetails_WhenExists_Returns200WithDto()
    {
        await _factory.SeedAsync(CreateEvent(
            id: 5,
            name: "Szczegóły Eventu",
            city: "Kraków"));
        AuthenticateAs("user", "user-42");

        var response = await _client.GetAsync("/api/v1/event/event-details/5");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var dto = await response.Content.ReadFromJsonAsync<getEventDetailsDto>(JsonOptions);
        Assert.That(dto, Is.Not.Null);
        Assert.That(dto!.eventId, Is.EqualTo(5));
        Assert.That(dto.nameOfEvent, Is.EqualTo("Szczegóły Eventu"));
        Assert.That(dto.city, Is.EqualTo("Kraków"));
        Assert.That(dto.country, Is.EqualTo("Poland"));
        Assert.That(dto.typeOfEvent, Is.EqualTo("music"));
        Assert.That(dto.urlOfEvent, Is.EqualTo("https://example.com/5"));
        Assert.That(dto.photoUrl, Is.EqualTo("https://img.example.com/5.jpg"));
        Assert.That(dto.address, Is.EqualTo("ul. Test 5"));
        Assert.That(dto.nameOfClub, Is.EqualTo("Club 5"));
    }

    [Test]
    public async Task EventDetails_WithAdmin_Returns200()
    {
        await _factory.SeedAsync(CreateEvent(8, "Admin View"));
        AuthenticateAs("admin", "admin-1");

        var response = await _client.GetAsync("/api/v1/event/event-details/8");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    // Constraint :min(0) – ujemne id zwykle 404 z routingu
    [Test]
    public async Task EventDetails_NegativeId_Returns404()
    {
        AuthenticateAs();

        var response = await _client.GetAsync("/api/v1/event/event-details/-1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }
}