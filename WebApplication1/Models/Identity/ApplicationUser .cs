using Microsoft.AspNetCore.Identity;

namespace WebApplication1.Models.Identity
{
    public class ApplicationUser : IdentityUser
    {
       
        public bool IsOAuth { get; set; }
        public string? GoogleId { get; set; }

        // Jeśli potrzebujesz relacji:
        public ICollection<UserEvent> UserEvents { get; set; } = new List<UserEvent>();
    }
}
