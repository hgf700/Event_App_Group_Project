using Backend.Db;
using Backend.Models.Dto.RelEvent;
using Backend.Models.Model;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Superpower.Model;
using System.Text.Json;

namespace Backend.Services;

public class SendOrDownloadFromApiService
{
    private readonly HttpClient _httpClient;
    private readonly ApplicationDbContext _context;

    public SendOrDownloadFromApiService(HttpClient httpClient,
        ApplicationDbContext context
        )
    {
        _httpClient = httpClient;
        _context = context;
    }

    public async Task<List<postSearchOrDownloadQueryDto>> FetchAndSaveEventsAsync(string? city = null)
    {
        if (string.IsNullOrWhiteSpace(city))
        {
            throw new ArgumentException("City is required");
        }

        string apiKey = Environment.GetEnvironmentVariable("TICKETMASTER_API_KEY");

        string baseUrl = "https://app.ticketmaster.com/discovery/v2/events.json";

        var query = new Dictionary<string, string?>
        {
            { "apikey", apiKey },
            { "size", "20" },
            { "city", city }
        };

        string url = QueryHelpers.AddQueryString(baseUrl, query);

        HttpResponseMessage response = await _httpClient.GetAsync(url);

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine($"Błąd API: {response.StatusCode}");
            return new List<postSearchOrDownloadQueryDto>();
        }

        string json = await response.Content.ReadAsStringAsync();

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        var ticketmasterData = JsonSerializer.Deserialize<TicketmasterResponse>(json, options);

        if (ticketmasterData?.Embedded?.Events == null ||
                !ticketmasterData.Embedded.Events.Any())
        {
            Console.WriteLine("Brak wydarzeń do zapisania.");
            return new List<postSearchOrDownloadQueryDto>();
        }

        var result = new List<postSearchOrDownloadQueryDto>();

        foreach (var ev in ticketmasterData.Embedded.Events)
        {
            bool exists = await _context.Events
                .AnyAsync(e => e.ExternalEventId == ev.Id);

            if (exists)
                continue;

            var venue = ev.Embedded?.Venues?.FirstOrDefault();

            var newEvent = new Event
            {
                ExternalEventId = ev.Id,
                TypeOfEvent = ev.Type,
                NameOfEvent = ev.Name,
                UrlOfEvent = ev.Url,
                PhotoUrl = ev.Images?.FirstOrDefault()?.Url,
                StartOfEvent = DateTime.TryParse(ev.Dates?.Start?.DateTime, out var eventStart)
                    ? eventStart.ToUniversalTime()
                    : DateTime.UtcNow,

                Address = venue?.Address?.Line1,
                City = venue?.City?.Name,
                Country = venue?.Country?.Name,
                NameOfClub = venue?.Name,
            };

            await _context.Events.AddAsync(newEvent);

            result.Add(new postSearchOrDownloadQueryDto
            {
                eventId = newEvent.Id,
                typeOfEvent = newEvent.TypeOfEvent,
                nameOfEvent = newEvent.NameOfEvent,
                urlOfEvent = newEvent.UrlOfEvent,
                photoUrl = newEvent.PhotoUrl,
                startOfEvent = newEvent.StartOfEvent,
                address = newEvent.Address,
                city = newEvent.City,
                country = newEvent.Country,
                nameOfClub = newEvent.NameOfClub
            });
        }

        await _context.SaveChangesAsync();

        return result;
    }
}