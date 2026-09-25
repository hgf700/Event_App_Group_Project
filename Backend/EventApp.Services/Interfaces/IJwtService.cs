using EventApp.Domain.Model;
using EventApp.Services.Model;

namespace EventApp.Services.Interfaces;

public interface IJwtService
{
    string GenerateToken(ApplicationUser user);
    string GenerateRefreshToken();
    string GenerateTokenFromRefreshToken(ApplicationUser user);

}