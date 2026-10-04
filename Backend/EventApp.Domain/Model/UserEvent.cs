using EventApp.Domain.Model;
using Microsoft.EntityFrameworkCore;

namespace EventApp.Services.Model;

[Index(nameof(UserId))]
[Index(nameof(EventId))]
public class UserEvent
{
    public int Id { get; set; }

    public string? UserId { get; set; } 
    public ApplicationUser User { get; set; } 
    public int? EventId { get; set; }
    public Event Event { get; set; } 

    public DateTime CreatedAt { get; set; }
    public DateTime? PaidAt { get; set; }
    public DateTime? CancelledAt { get; set; }
    public StatesOfTicket State { get; set; }
    public string? PaymentId { get; set; }
}

public enum StatesOfTicket
{
    Pending = 0,
    Paid = 1,
    Cancelled = 2,
    Expired = 3
}