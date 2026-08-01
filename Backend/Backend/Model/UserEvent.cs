using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace Backend.Model;

[Index(nameof(UserId))]
[Index(nameof(EventId))]
public class UserEvent
{
    public string? UserId { get; set; }
    public ApplicationUser User { get; set; } 

    public int? EventId { get; set; }
    public Event Event { get; set; } 
}
