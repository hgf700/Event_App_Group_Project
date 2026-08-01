using Backend.Interfaces;
using Backend.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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
    private readonly string _jwtSecret;

    public JwtService()
    {
        _jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")
            ?? throw new InvalidOperationException("JWT_SECRET is not set.");
    }

    //developing 
    //dodac role do jwt i chyba potem do local storage?

    public string GenerateToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email!)
        };

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_jwtSecret));

        var creds = new SigningCredentials(
            key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddDays(7),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public string GenerateTokenFromRefreshToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email!)
        };

        var key = new SymmetricSecurityKey(
           Encoding.UTF8.GetBytes(_jwtSecret));

        var creds = new SigningCredentials(
            key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
             claims: claims,
             expires: DateTime.UtcNow.AddDays(7),
             signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}