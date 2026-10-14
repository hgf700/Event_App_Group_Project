using EventApp.Domain.Model;
using EventApp.Services.Model;

namespace EventApp.Services.Interfaces;

public interface IJwtService
{
    Task<string> GenerateToken(ApplicationUser user);
    string GenerateRefreshToken();
}