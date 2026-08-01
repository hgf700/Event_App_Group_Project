using System.ComponentModel.DataAnnotations;

namespace Backend.Dto.RelEvent;

public class getEventTicketWithQrDto
{
    public int? eventId { get; set; }
    public string? typeOfEvent { get; set; }
    public string? nameOfEvent { get; set; }
    public DateTime? startOfEvent { get; set; }
    public string? address { get; set; }
    public string? city { get; set; }
    public string? nameOfClub { get; set; }
    public string? urlOfEvent { get; set; }
    public byte[]? qrCode { get; set; }
}
