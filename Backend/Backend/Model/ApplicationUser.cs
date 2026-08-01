using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace Backend.Model;

//[Index(nameof(EventId))]
public class ApplicationUser : IdentityUser
{
    public bool IsOAuth { get; set; }
    public string? GoogleId { get; set; }
    public ICollection<UserEvent> UserEvents { get; set; } = new List<UserEvent>();
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
