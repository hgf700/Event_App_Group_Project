using Backend.Identity;

namespace Backend.Models.Model;

public class UserEvent
{
    public string UserId { get; set; }
    public ApplicationUser User { get; set; }

    public int EventId { get; set; }
    public Event Event { get; set; }
}
