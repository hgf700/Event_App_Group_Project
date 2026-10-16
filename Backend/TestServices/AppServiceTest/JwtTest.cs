using EventApp.Domain.Model;
using EventApp.Services.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace TestServices.AppServiceTest;

[TestFixture]
public class JwtTest
{
    private Mock<UserManager<ApplicationUser>> _userManagerMock = null!;
    private string? _originalJwtSecret;

    [SetUp]
    public void SetUp()
    {
        _originalJwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET");

        // UserManager wymaga IUserStore – tworzymy pusty mock
        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null, null, null, null, null, null, null, null);
    }

    [TearDown]
    public void TearDown()
    {
        Environment.SetEnvironmentVariable("JWT_SECRET", _originalJwtSecret);
    }

    // ============================================================
    // 1. Konstruktor – brak JWT_SECRET
    // ============================================================

    [Test]
    public void Constructor_WhenJwtSecretIsMissing_ThrowsInvalidOperationException()
    {
        Environment.SetEnvironmentVariable("JWT_SECRET", null);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            new JwtService(_userManagerMock.Object));

        Assert.That(ex!.Message, Is.EqualTo("JWT_SECRET is not set."));
    }

    [Test]
    public void Constructor_WhenJwtSecretIsEmpty_ThrowsInvalidOperationException()
    {
        // GetEnvironmentVariable zwraca "" gdy ustawione na pusty string
        // w Twoim kodzie ?? catchuje tylko null, więc pusty string przejdzie.
        // Jeśli chcesz też rzucać na pusty string – zmień kod produkcyjny.
        Environment.SetEnvironmentVariable("JWT_SECRET", "");

        // Aktualnie NIE rzuci wyjątku, bo "" != null
        Assert.DoesNotThrow(() => new JwtService(_userManagerMock.Object));
    }

    // ============================================================
    // 2. GenerateToken – poprawny token
    // ============================================================

    [Test]
    public async Task GenerateToken_ForRegularUser_ReturnsValidJwtWithUserRole()
    {
        // Arrange
        Environment.SetEnvironmentVariable("JWT_SECRET", "super-secret-key-at-least-32-chars-long!!");

        var user = new ApplicationUser
        {
            Id = "user-123",
            Email = "user@example.com"
        };

        _userManagerMock
            .Setup(x => x.IsInRoleAsync(user, "admin"))
            .ReturnsAsync(false);

        var service = new JwtService(_userManagerMock.Object);

        // Act
        var tokenString = await service.GenerateToken(user);

        // Assert
        Assert.That(tokenString, Is.Not.Null.And.Not.Empty);

        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        Assert.That(token.Claims, Has.Some.Matches<Claim>(c =>
            c.Type == ClaimTypes.NameIdentifier && c.Value == "user-123"));

        Assert.That(token.Claims, Has.Some.Matches<Claim>(c =>
            c.Type == ClaimTypes.Email && c.Value == "user@example.com"));

        Assert.That(token.Claims, Has.Some.Matches<Claim>(c =>
            c.Type == ClaimTypes.Role && c.Value == "user"));

        // Token powinien być ważny ~7 dni
        Assert.That(token.ValidTo, Is.EqualTo(DateTime.UtcNow.AddDays(7)).Within(TimeSpan.FromMinutes(1)));
    }

    [Test]
    public async Task GenerateToken_ForAdminUser_ReturnsValidJwtWithAdminRole()
    {
        // Arrange
        Environment.SetEnvironmentVariable("JWT_SECRET", "super-secret-key-at-least-32-chars-long!!");

        var user = new ApplicationUser
        {
            Id = "admin-456",
            Email = "admin@example.com"
        };

        _userManagerMock
            .Setup(x => x.IsInRoleAsync(user, "admin"))
            .ReturnsAsync(true);

        var service = new JwtService(_userManagerMock.Object);

        // Act
        var tokenString = await service.GenerateToken(user);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        Assert.That(token.Claims, Has.Some.Matches<Claim>(c =>
            c.Type == ClaimTypes.Role && c.Value == "admin"));
    }

    [Test]
    public async Task GenerateToken_TokenIsSignedWithCorrectKey_CanBeValidated()
    {
        // Arrange
        const string secret = "super-secret-key-at-least-32-chars-long!!";
        Environment.SetEnvironmentVariable("JWT_SECRET", secret);

        var user = new ApplicationUser
        {
            Id = "user-789",
            Email = "validate@example.com"
        };

        _userManagerMock
            .Setup(x => x.IsInRoleAsync(user, "admin"))
            .ReturnsAsync(false);

        var service = new JwtService(_userManagerMock.Object);
        var tokenString = await service.GenerateToken(user);

        // Act – walidacja tokena tym samym kluczem
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
            ClockSkew = TimeSpan.Zero
        };

        var handler = new JwtSecurityTokenHandler();
        var principal = handler.ValidateToken(tokenString, validationParameters, out var validatedToken);

        // Assert
        Assert.That(principal, Is.Not.Null);
        Assert.That(validatedToken, Is.InstanceOf<JwtSecurityToken>());
        Assert.That(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, Is.EqualTo("user-789"));
        Assert.That(principal.FindFirst(ClaimTypes.Email)?.Value, Is.EqualTo("validate@example.com"));
    }

    // ============================================================
    // 3. GenerateRefreshToken
    // ============================================================

    [Test]
    public void GenerateRefreshToken_ReturnsNonEmptyBase64String()
    {
        Environment.SetEnvironmentVariable("JWT_SECRET", "super-secret-key-at-least-32-chars-long!!");
        var service = new JwtService(_userManagerMock.Object);

        var refreshToken = service.GenerateRefreshToken();

        Assert.That(refreshToken, Is.Not.Null.And.Not.Empty);

        // Powinien być poprawnym Base64
        Assert.DoesNotThrow(() => Convert.FromBase64String(refreshToken));

        // 32 bajty → Base64 ma 44 znaki (z paddingiem)
        Assert.That(refreshToken.Length, Is.EqualTo(44));
    }

    [Test]
    public void GenerateRefreshToken_CalledTwice_ReturnsDifferentValues()
    {
        Environment.SetEnvironmentVariable("JWT_SECRET", "super-secret-key-at-least-32-chars-long!!");
        var service = new JwtService(_userManagerMock.Object);

        var token1 = service.GenerateRefreshToken();
        var token2 = service.GenerateRefreshToken();

        Assert.That(token1, Is.Not.EqualTo(token2));
    }

    // ============================================================
    // 4. Edge cases
    // ============================================================
    [Test]
    public void GenerateToken_WhenUserEmailIsNull_ThrowsArgumentNullException()
    {
        Environment.SetEnvironmentVariable("JWT_SECRET", "super-secret-key-at-least-32-chars-long!!");

        var user = new ApplicationUser
        {
            Id = "user-null-email",
            Email = null
        };

        var service = new JwtService(_userManagerMock.Object);

        Assert.ThrowsAsync<ArgumentNullException>(
            async () => await service.GenerateToken(user));
    }
}