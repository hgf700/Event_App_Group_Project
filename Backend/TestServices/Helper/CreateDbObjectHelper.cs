using EventApp.Domain.Model;
using EventApp.Services.Model;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestServices.Helper;

public class CreateDbObjectHelper
{
    private HttpClient _client = null!;

    public CreateDbObjectHelper(HttpClient client)
    {
        _client = client;
    }

    public void AuthenticateAs(string role = "user", string userId = "user-1")
    {
        _client.DefaultRequestHeaders.Remove("Authorization");
        _client.DefaultRequestHeaders.Add("Authorization", $"Test {role}|{userId}");
    }

    public Event CreateEvent(int id = 1, string name = "Event", string? city = "Warszawa", DateTime? start = null)
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

    public Bookmark CreateBookmark(int id = 1, string userId = "user-1", int eventId = 1)
    {
        return new Bookmark
        {
            Id = id,
            UserId = userId,
            EventId = eventId
        };
    }

    public UserEvent CreateUserEvent(int id = 1, string userId = "user-1", int eventId = 1)
    {
        return new UserEvent
        {
            Id = id,
            UserId = userId,
            EventId = eventId
        };
    }
}
