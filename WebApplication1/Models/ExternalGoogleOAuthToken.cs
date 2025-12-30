using WebApplication1.Models.Identity;

public class ExternalGoogleOAuthToken
{
    public int Id { get; set; }
    public string UserId { get; set; } = null!;
    public ApplicationUser User { get; set; } = null!;
    public string Provider { get; set; } = "Google";

    public string RefreshTokenEncrypted { get; set; } = string.Empty!;  // <<< Nie null
    public string? AccessTokenEncrypted { get; set; }
    public DateTime? AccessTokenExpiresAt { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}