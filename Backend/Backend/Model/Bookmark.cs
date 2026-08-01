namespace Backend.Model;

public class Bookmark
{
    public int Id { get; set; }
    public string? UserId { get; set; }
    public ApplicationUser User { get; set; }
    public int? EventId{ get; set; }
    public Event Event { get; set; }

}
