namespace Backend.Models.Dto.RelEvent;

public class getUserBoughtTickets
{
    public int? eventId { get; set; }
    public string? typeOfEvent { get; set; }
    public string? nameOfEvent { get; set; }
    public DateTime? startOfEvent { get; set; }
    public string? address { get; set; }
    public string? city { get; set; }
    public string? nameOfClub { get; set; }
}
