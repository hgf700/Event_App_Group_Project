using EventApp.Domain.Model;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace EventApp.Services.Model;

[Index(nameof(UserId))]
[Index(nameof(EventId))]
[Index(nameof(PaymentId))]
public class UserEvent
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    public string? UserId { get; set; } 
    public ApplicationUser User { get; set; } 

    public int? EventId { get; set; }
    public Event Event { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime? PaymentStateAt { get; set; }

    public StatesOfTicket PaymentState { get; set; }

    public DateTime? TicketStateAt { get; set; }

    public TicketState TicketState { get; set; }

    public string? PaymentId { get; set; }
}

public enum StatesOfTicket
{
    Pending = 0,
    Paid = 1,
    Cancelled = 2,
    Expired = 3,
    Refunded = 4
}

public enum TicketState
{
    NotIssued = 0,
    Active = 1,
    Used = 2,
    Cancelled = 3
}