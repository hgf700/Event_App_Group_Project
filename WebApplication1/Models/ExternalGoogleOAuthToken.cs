using WebApplication1.Models.Identity;

namespace WebApplication1.Models
{
    public class ExternalGoogleOAuthToken
    {
        public int Id { get; set; }

        // FK do AspNetUsers
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }

        // Provider: "Google", "GitHub"
        public string Provider { get; set; }

        // 🔐 SZYFROWANE
        public string RefreshTokenEncrypted { get; set; }

        // Opcjonalnie cache access tokena
        public string AccessTokenEncrypted { get; set; }
        public DateTime? AccessTokenExpiresAt { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }

}
