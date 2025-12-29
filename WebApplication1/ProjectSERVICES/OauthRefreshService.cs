using Microsoft.AspNetCore.Identity;
using System.Text.Json;
using WebApplication1.Areas.Identity.Data;
using WebApplication1.Models;
using WebApplication1.Models.Identity;
using static System.Net.WebRequestMethods;

namespace WebApplication1.ProjectSERVICES
{
    public class OauthRefreshService
    {
        private readonly ApplicationDbContext _context;
        public OauthRefreshService(
                ApplicationDbContext context
            )
        {
            context = _context;
        }
        //public async Task<string> GetValidAccessTokenAsync(string userId)
        //{
        //    var token = await _context.GoogleTokens.FindAsync(userId);

        //    if (token.ExpiresAt > DateTime.UtcNow.AddMinutes(1))
        //        return token.AccessToken;

        //    var response = await _http.PostAsync(
        //        "https://oauth2.googleapis.com/token",
        //        new FormUrlEncodedContent(new Dictionary<string, string>
        //        {
        //            ["client_id"] = _clientId,
        //            ["client_secret"] = _clientSecret,
        //            ["refresh_token"] = token.RefreshToken,
        //            ["grant_type"] = "refresh_token"
        //        })
        //    );

        //    var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        //    token.AccessToken = json.RootElement.GetProperty("access_token").GetString();
        //    token.ExpiresAt = DateTime.UtcNow.AddSeconds(
        //        json.RootElement.GetProperty("expires_in").GetInt32()
        //    );

        //    await _db.SaveChangesAsync();
        //    return token.AccessToken;
        //}

    }
}
