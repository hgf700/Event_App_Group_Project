using Backend.Identity;

namespace Backend.Models.Model;

public class Bookmark
{
    public int Id { get; set; }
    public int? UserId { get; set; }
    public ApplicationUser User { get; set; }
    

}
