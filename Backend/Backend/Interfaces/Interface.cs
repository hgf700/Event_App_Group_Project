using Backend.Model;

namespace Backend.Interfaces;

public interface IJwtService
{
    string GenerateToken(ApplicationUser user);
    string GenerateRefreshToken();
    string GenerateTokenFromRefreshToken(ApplicationUser user);

}