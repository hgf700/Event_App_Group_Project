using Backend.Db;
using Backend.Models.Model;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace Backend.Services;

public class SeedDbService
{
    private readonly HttpClient _httpClient;
    private readonly ApplicationDbContext _context;

    public SeedDbService(HttpClient httpClient,
        ApplicationDbContext context
        )
    {
        _httpClient = httpClient;
        _context = context;
    }

    public async Task FetchAndSaveEventsAsync()
    {
        try
        {
            string? apiKey = Environment.GetEnvironmentVariable("TICKETMASTER_API_KEY");

            if (string.IsNullOrWhiteSpace(apiKey))
            {
                Console.WriteLine("Brak TICKETMASTER_API_KEY");
                return;
            }

            string baseUrl = "https://app.ticketmaster.com/discovery/v2/events.json";

            var query = new Dictionary<string, string?>
            {
                { "apikey", apiKey },
                { "size", "20" },
                { "countryCode", "PL" }
            };

            string url = QueryHelpers.AddQueryString(baseUrl, query);

            HttpResponseMessage response = await _httpClient.GetAsync(url);

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"Błąd API: {response.StatusCode}");
                return;
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
                return;
            }

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
                    StartOfEvent = DateTime.TryParse(
                        ev.Dates?.Start?.DateTime,
                        out var eventStart)
                        ? eventStart.ToUniversalTime()
                        : DateTime.UtcNow,

                    Address = venue?.Address?.Line1,
                    City = venue?.City?.Name,
                    Country = venue?.Country?.Name,
                    NameOfClub = venue?.Name,
                };

                await _context.Events.AddAsync(newEvent);
            }

            await _context.SaveChangesAsync();

            Console.WriteLine("Wydarzenia zostały zapisane.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Błąd podczas seedowania danych: {ex.Message}");
        }
    }
}