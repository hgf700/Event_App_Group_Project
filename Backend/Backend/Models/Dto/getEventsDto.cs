using System.ComponentModel.DataAnnotations;

namespace Backend.Models.Dto;

public class getEventsDto
{
    public string? TypeOfEvent { get; set; }
    public string? NameOfEvent { get; set; }

    [Url]
    public string? UrlOfEvent { get; set; }

    [Url]
    public string? PhotoUrl { get; set; }
    public DateTime? StartOfEvent { get; set; }
    public string? Address { get; set; }
    public string? City { get; set; }
    public string? Country { get; set; }
    public string? NameOfClub { get; set; }
}
