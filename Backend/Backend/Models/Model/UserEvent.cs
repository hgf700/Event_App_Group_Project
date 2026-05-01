using Backend.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace Backend.Models.Model;

[Index(nameof(UserId))]
[Index(nameof(EventId))]
public class UserEvent
{
    //[Required]
    public string UserId { get; set; }
    public ApplicationUser User { get; set; } 

    //[Required]
    public int EventId { get; set; }
    public Event Event { get; set; } 
}
