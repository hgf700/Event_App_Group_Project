using Backend.Identity;
using Backend.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Backend.Services;

//public class JwtService
//{
//       dziala
//    string JWT_SECRET = Environment.GetEnvironmentVariable("JWT_SECRET");

//    public string GenerateToken(ApplicationUser user)
//    {
//        var claims = new[]
//        {
//            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
//            new Claim(ClaimTypes.Email, user.Email)
//        };

//        var key = new SymmetricSecurityKey(
//            Encoding.UTF8.GetBytes(JWT_SECRET));

//        var creds = new SigningCredentials(
//            key, SecurityAlgorithms.HmacSha256Signature);

//        var token = new JwtSecurityToken(
//            claims: claims,
//            expires: DateTime.UtcNow.AddMinutes(15),
//            signingCredentials: creds);

//        return new JwtSecurityTokenHandler().WriteToken(token);
//    }
//}

public class JwtService : IJwtService
{
    //developing
    public string GenerateToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email!)
        };

        string JWT_SECRET = Environment.GetEnvironmentVariable("JWT_SECRET");

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(JWT_SECRET));

        var creds = new SigningCredentials(
            key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddDays(7),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}