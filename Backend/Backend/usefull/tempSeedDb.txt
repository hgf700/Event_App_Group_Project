using Backend.Db;
using Backend.Models.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace Backend.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class SeedDataController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly HttpClient _httpClient;

    public SeedDataController(
        ApplicationDbContext context,
        IHttpClientFactory httpClientFactory)
    {
        _context = context;
        _httpClient = httpClientFactory.CreateClient();
    }

    [HttpPost("import-events")]
    public async Task<ActionResult> ImportEvents(
        [FromQuery] string city = "Warsaw",
        [FromQuery] int size = 20,
        [FromQuery] int page = 1)
    {
        try
        {
            string? apiKey =
                Environment.GetEnvironmentVariable("TICKETMASTER_API_KEY");

            if (string.IsNullOrWhiteSpace(apiKey))
            {
                return BadRequest(new
                {
                    message = "Missing Ticketmaster API key"
                });
            }

            string baseUrl =
                "https://app.ticketmaster.com/discovery/v2/events.json";

            var query = new Dictionary<string, string>
            {
                { "apikey", apiKey },
                { "city", city },
                { "size", size.ToString() },
                { "page", page.ToString() },
                { "sort", "date,asc" }
            };

            string url = QueryHelpers.AddQueryString(baseUrl, query);

            HttpResponseMessage response =
                await _httpClient.GetAsync(url);

            string json =
                await response.Content.ReadAsStringAsync();

            // 🔥 DEBUG RESPONSE (bardzo ważne)
            if (!response.IsSuccessStatusCode)
            {
                return StatusCode((int)response.StatusCode, new
                {
                    message = "Ticketmaster API error",
                    status = response.StatusCode,
                    response = json
                });
            }

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            var ticketmasterResponse =
                JsonSerializer.Deserialize<TicketmasterResponse>(json, options);

            if (ticketmasterResponse?.Embedded?.Events == null)
            {
                return BadRequest(new
                {
                    message = "Invalid Ticketmaster response structure",
                    raw = json
                });
            }

            var externalEvents =
                ticketmasterResponse.Embedded.Events;

            var existingIds = await _context.Events
                .Select(e => e.ExternalEventId)
                .ToHashSetAsync();

            var newEvents = externalEvents
                .Where(ev => !existingIds.Contains(ev.Id))
                .Select(ev =>
                {
                    var venue = ev.Embedded?.Venues?.FirstOrDefault();

                    return new Event
                    {
                        ExternalEventId = ev.Id,
                        NameOfEvent = ev.Name,
                        TypeOfEvent = ev.Type,
                        UrlOfEvent = ev.Url,
                        PhotoUrl = ev.Images?.FirstOrDefault()?.Url,

                        StartOfEvent =
                            DateTime.TryParse(ev.Dates?.Start?.DateTime, out var startDate)
                                ? startDate
                                : DateTime.UtcNow,

                        NameOfClub = venue?.Name,
                        Address = venue?.Address?.Line1,
                        City = venue?.City?.Name,
                        Country = venue?.Country?.Name
                    };
                })
                .ToList();

            if (newEvents.Any())
            {
                await _context.Events.AddRangeAsync(newEvents);
                await _context.SaveChangesAsync();
            }

            return Ok(new
            {
                city,
                imported = newEvents.Count,
                totalFetched = externalEvents.Count,
                skippedDuplicates = externalEvents.Count - newEvents.Count
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new
            {
                message = ex.Message,
                stack = ex.StackTrace
            });
        }
    }
}