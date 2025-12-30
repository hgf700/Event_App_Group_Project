using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using WebApplication1.Areas.Identity.Data;
using WebApplication1.Models;
using WebApplication1.ProjectSERVICES;

public class OauthRefreshService
{
    private readonly ApplicationDbContext _context;
    private readonly TokenEncryptionService _encryption;

    public OauthRefreshService(ApplicationDbContext context, TokenEncryptionService encryption)
    {
        _context = context;
        _encryption = encryption;
    }

    public async Task<string> EnsureValidAccessTokenAsync(string userId)
    {
        var record = await _context.ExternalGoogleOAuthTokens
            .FirstOrDefaultAsync(t => t.UserId == userId && t.Provider == "Google");

        if (record == null)
            throw new InvalidOperationException("Brak refresh tokena – użytkownik nie logował się przez Google");

        // Jeśli mamy ważny access token – zwróć go
        if (record.AccessTokenExpiresAt.HasValue &&
            record.AccessTokenExpiresAt.Value > DateTime.UtcNow.AddMinutes(5) &&
            !string.IsNullOrEmpty(record.AccessTokenEncrypted))
        {
            return _encryption.Decrypt(record.AccessTokenEncrypted);
        }

        // W przeciwnym razie – odśwież
        var refreshToken = _encryption.Decrypt(record.RefreshTokenEncrypted);

        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID")!,
            ["client_secret"] = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET")!,
            ["refresh_token"] = refreshToken,
            ["grant_type"] = "refresh_token"
        };

        using var client = new HttpClient();
        var content = new FormUrlEncodedContent(parameters);
        var response = await client.PostAsync("https://oauth2.googleapis.com/token", content);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException("Nie udało się odświeżyć tokena Google");

        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        var newAccessToken = json.GetProperty("access_token").GetString()!;
        var expiresIn = json.GetProperty("expires_in").GetInt32();

        // Zapisz nowy access token
        record.AccessTokenEncrypted = _encryption.Encrypt(newAccessToken);
        record.AccessTokenExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn);
        record.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        return newAccessToken;
    }
    public async Task SaveRefreshTokenAsync(string userId, string refreshToken)
    {
        var record = await _context.ExternalGoogleOAuthTokens
            .FirstOrDefaultAsync(t => t.UserId == userId && t.Provider == "Google");

        if (record == null)
        {
            record = new ExternalGoogleOAuthToken
            {
                UserId = userId,
                Provider = "Google",
                RefreshTokenEncrypted = _encryption.Encrypt(refreshToken),  // <<< USTAW OD RAZU
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
            _context.ExternalGoogleOAuthTokens.Add(record);
        }
        else
        {
            // Aktualizuj istniejący (jeśli masz nowy token)
            record.RefreshTokenEncrypted = _encryption.Encrypt(refreshToken);
            record.UpdatedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();
    }
}
//ExternalGoogleOAuthTokens