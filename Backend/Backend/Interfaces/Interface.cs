using Backend.Identity;

namespace Backend.Interfaces;

public interface IJwtService
{
    string GenerateToken(ApplicationUser user);
}