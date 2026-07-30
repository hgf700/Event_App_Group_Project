using System.ComponentModel.DataAnnotations;

namespace Backend.Dto.RelEvent;

public class getSingleEventDto
{
    public string? typeOfEvent { get; set; }
    public string? nameOfEvent { get; set; }

    [Url]
    public string? urlOfEvent { get; set; }

    [Url]
    public string? photoUrl { get; set; }
    public DateTime? startOfEvent { get; set; }
    public string? address { get; set; }
    public string? city { get; set; }
    public string? country { get; set; }
    public string? nameOfClub { get; set; }
}