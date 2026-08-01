namespace Backend.Model;

public class NotificationLog
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public ApplicationUser? User { get; set; }
    public int EventId { get; set; }
    public Event? Event { get; set; }
    public bool EmailSent { get; set; }
    public bool SmsSent { get; set; }
    public DateTime CreatedAt { get; set; }
    public string? ErrorMessage { get; set; }
}
