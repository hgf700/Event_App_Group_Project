using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Services;
using EventApp.Services.Services.model;
using EventApp.Services.Services.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace TestServices.ServiceTest;

[TestFixture]
public class AuthTest
{
    private Mock<UserManager<ApplicationUser>> _userManagerMock = null!;
    private Mock<IJwtService> _jwtServiceMock = null!;
    private Mock<ILogger<AuthService>> _loggerMock = null!;
    private ApplicationDbContext _context = null!;
    private AuthService _service = null!;

    [SetUp]
    public void SetUp()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _jwtServiceMock = new Mock<IJwtService>();
        _loggerMock = new Mock<ILogger<AuthService>>();

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _context = new ApplicationDbContext(options);

        _service = new AuthService(
            _userManagerMock.Object,
            _jwtServiceMock.Object,
            _loggerMock.Object,
            _context);
    }

    [TearDown]
    public void TearDown()
    {
        _context.Dispose();
    }

    private static ApplicationUser CreateUser(
        string id = "user-1",
        string email = "user@example.com")
    {
        return new ApplicationUser
        {
            Id = id,
            UserName = email,
            Email = email,
            IsOAuth = false
        };
    }

    private void SetupJwt(ApplicationUser user, string jwt = "jwt-token", string refresh = "refresh-token")
    {
        _jwtServiceMock
            .Setup(x => x.GenerateToken(user))
            .ReturnsAsync(jwt);

        _jwtServiceMock
            .Setup(x => x.GenerateRefreshToken())
            .Returns(refresh);
    }

    // ============================================================
    // RegisterNormalAsync
    // ============================================================

    [Test]
    public async Task RegisterNormalAsync_WhenUserAlreadyExists_ReturnsUserAlreadyExists()
    {
        var dto = new postCreateUserNormDto
        {
            email = "exists@example.com",
            password = "Password1!"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(dto.email))
            .ReturnsAsync(CreateUser(email: dto.email));

        var result = await _service.RegisterNormalAsync(dto);

        Assert.That(result.UserAlreadyExists, Is.True);
        Assert.That(result.Response, Is.Null);
        Assert.That(result.Errors, Is.Null);
    }

    [Test]
    public async Task RegisterNormalAsync_WhenCreateFails_ReturnsErrors()
    {
        var dto = new postCreateUserNormDto
        {
            email = "new@example.com",
            password = "weak"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(dto.email))
            .ReturnsAsync((ApplicationUser?)null);

        var identityErrors = new[]
        {
            new IdentityError { Code = "PasswordTooShort", Description = "Password too short" }
        };

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), dto.password))
            .ReturnsAsync(IdentityResult.Failed(identityErrors));

        var result = await _service.RegisterNormalAsync(dto);

        Assert.That(result.UserAlreadyExists, Is.False);
        Assert.That(result.Errors, Is.Not.Null);
        Assert.That(result.Errors!.Any(e => e.Code == "PasswordTooShort"), Is.True);
        Assert.That(result.Response, Is.Null);
    }

    [Test]
    public async Task RegisterNormalAsync_WhenSuccess_ReturnsTokensAndSavesRefreshToken()
    {
        var dto = new postCreateUserNormDto
        {
            email = "new@example.com",
            password = "Password1!"
        };

        ApplicationUser? createdUser = null;

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(dto.email))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), dto.password))
            .ReturnsAsync(IdentityResult.Success)
            .Callback<ApplicationUser, string>((u, _) =>
            {
                u.Id = "new-user-id";
                createdUser = u;
            });

        _userManagerMock
            .Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "user"))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "user" });

        _jwtServiceMock
            .Setup(x => x.GenerateToken(It.IsAny<ApplicationUser>()))
            .ReturnsAsync("jwt-abc");

        _jwtServiceMock
            .Setup(x => x.GenerateRefreshToken())
            .Returns("refresh-xyz");

        var result = await _service.RegisterNormalAsync(dto);

        Assert.That(result.UserAlreadyExists, Is.False);
        Assert.That(result.Errors, Is.Null);
        Assert.That(result.Response, Is.Not.Null);
        Assert.That(result.Response!.jwt, Is.EqualTo("jwt-abc"));
        Assert.That(result.Response.refreshToken, Is.EqualTo("refresh-xyz"));
        Assert.That(result.Response.email, Is.EqualTo(dto.email));
        Assert.That(result.Response.userRole, Is.EqualTo("user"));

        // Refresh token w DB
        var tokens = await _context.RefreshTokens.ToListAsync();
        Assert.That(tokens, Has.Count.EqualTo(1));
        Assert.That(tokens[0].Token, Is.EqualTo("refresh-xyz"));
        Assert.That(tokens[0].UserId, Is.EqualTo("new-user-id"));
        Assert.That(tokens[0].Expires, Is.EqualTo(DateTime.UtcNow.AddDays(30)).Within(TimeSpan.FromMinutes(1)));

        _userManagerMock.Verify(
            x => x.CreateAsync(
                It.Is<ApplicationUser>(u =>
                    u.Email == dto.email &&
                    u.UserName == dto.email &&
                    u.IsOAuth == false),
                dto.password),
            Times.Once);

        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "user"), Times.Once);
    }

    // ============================================================
    // LoginNormalAsync
    // ============================================================

    [Test]
    public async Task LoginNormalAsync_WhenUserNotFound_ReturnsIncorrectCredentials()
    {
        var dto = new postLoginUserNormDto
        {
            email = "missing@example.com",
            password = "pass"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(dto.email))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _service.LoginNormalAsync(dto);

        Assert.That(result.IncorrectUserCredentials, Is.True);
        Assert.That(result.Response, Is.Null);
    }

    [Test]
    public async Task LoginNormalAsync_WhenPasswordInvalid_ReturnsIncorrectCredentials()
    {
        var dto = new postLoginUserNormDto
        {
            email = "user@example.com",
            password = "wrong"
        };

        var user = CreateUser(email: dto.email);

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(dto.email))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.CheckPasswordAsync(user, dto.password))
            .ReturnsAsync(false);

        var result = await _service.LoginNormalAsync(dto);

        Assert.That(result.IncorrectUserCredentials, Is.True);
        Assert.That(result.Response, Is.Null);
    }

    [Test]
    public async Task LoginNormalAsync_WhenSuccess_AndHasValidRefreshToken_ReusesIt()
    {
        var dto = new postLoginUserNormDto
        {
            email = "user@example.com",
            password = "Password1!"
        };

        var user = CreateUser(id: "u-1", email: dto.email);

        _userManagerMock.Setup(x => x.FindByEmailAsync(dto.email)).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.CheckPasswordAsync(user, dto.password)).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "user")).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "admin")).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "user" });
        SetupJwt(user, "jwt-login", "should-not-be-used");

        // Istniejący ważny refresh token
        _context.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            Token = "existing-refresh",
            Expires = DateTime.UtcNow.AddDays(10),
            Created = DateTime.UtcNow.AddDays(-1),
            Revoked = null
        });
        await _context.SaveChangesAsync();

        var result = await _service.LoginNormalAsync(dto);

        Assert.That(result.IncorrectUserCredentials, Is.False);
        Assert.That(result.Response, Is.Not.Null);
        Assert.That(result.Response!.jwt, Is.EqualTo("jwt-login"));
        Assert.That(result.Response.refreshToken, Is.EqualTo("existing-refresh"));
        Assert.That(result.Response.email, Is.EqualTo(dto.email));
        Assert.That(result.Response.userRole, Is.EqualTo("user"));

        // Nie tworzy nowego refresh tokena
        Assert.That(await _context.RefreshTokens.CountAsync(), Is.EqualTo(1));
        _jwtServiceMock.Verify(x => x.GenerateRefreshToken(), Times.Never);
    }

    [Test]
    public async Task LoginNormalAsync_WhenNoValidRefreshToken_CreatesNewOne()
    {
        var dto = new postLoginUserNormDto
        {
            email = "user@example.com",
            password = "Password1!"
        };

        var user = CreateUser(id: "u-2", email: dto.email);

        _userManagerMock.Setup(x => x.FindByEmailAsync(dto.email)).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.CheckPasswordAsync(user, dto.password)).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "user")).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "admin")).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "user" });
        SetupJwt(user, "jwt-new", "new-refresh");

        // Wygasły token – nie powinien być użyty
        _context.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            Token = "expired",
            Expires = DateTime.UtcNow.AddDays(-1),
            Created = DateTime.UtcNow.AddDays(-40),
            Revoked = null
        });
        await _context.SaveChangesAsync();

        var result = await _service.LoginNormalAsync(dto);

        Assert.That(result.Response!.refreshToken, Is.EqualTo("new-refresh"));
        Assert.That(await _context.RefreshTokens.CountAsync(t => t.Token == "new-refresh"), Is.EqualTo(1));
    }

    [Test]
    public async Task LoginNormalAsync_WhenUserHasNoRole_AddsUserRole()
    {
        var dto = new postLoginUserNormDto
        {
            email = "norole@example.com",
            password = "Password1!"
        };

        var user = CreateUser(id: "u-3", email: dto.email);

        _userManagerMock.Setup(x => x.FindByEmailAsync(dto.email)).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.CheckPasswordAsync(user, dto.password)).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "user")).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "admin")).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.AddToRoleAsync(user, "user")).ReturnsAsync(IdentityResult.Success);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "user" });
        SetupJwt(user);

        var result = await _service.LoginNormalAsync(dto);

        Assert.That(result.Response, Is.Not.Null);
        _userManagerMock.Verify(x => x.AddToRoleAsync(user, "user"), Times.Once);
    }

    [Test]
    public async Task LoginNormalAsync_WhenRevokedRefreshTokenExists_CreatesNewOne()
    {
        var dto = new postLoginUserNormDto
        {
            email = "user@example.com",
            password = "Password1!"
        };

        var user = CreateUser(id: "u-4", email: dto.email);

        _userManagerMock.Setup(x => x.FindByEmailAsync(dto.email)).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.CheckPasswordAsync(user, dto.password)).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "user")).ReturnsAsync(true);
        _userManagerMock.Setup(x => x.IsInRoleAsync(user, "admin")).ReturnsAsync(false);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "user" });
        SetupJwt(user, "jwt", "fresh-refresh");

        _context.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            Token = "revoked-token",
            Expires = DateTime.UtcNow.AddDays(20),
            Created = DateTime.UtcNow,
            Revoked = DateTime.UtcNow.AddHours(-1) // revoked
        });
        await _context.SaveChangesAsync();

        var result = await _service.LoginNormalAsync(dto);

        Assert.That(result.Response!.refreshToken, Is.EqualTo("fresh-refresh"));
    }

    // ============================================================
    // LoginGoogleOauth
    // ============================================================

    private static ClaimsPrincipal CreateGooglePrincipal(
        string? email = "google@example.com",
        string? googleId = "google-id-123")
    {
        var claims = new List<Claim>();
        if (email != null)
            claims.Add(new Claim(ClaimTypes.Email, email));
        if (googleId != null)
            claims.Add(new Claim(ClaimTypes.NameIdentifier, googleId));

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Google"));
    }

    [Test]
    public async Task LoginGoogleOauth_WhenEmailMissing_ReturnsError()
    {
        var principal = CreateGooglePrincipal(email: null, googleId: "gid");

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Response, Is.Null);
        Assert.That(result.Errors, Is.Not.Null);
        Assert.That(result.Errors!.Any(e => e.Code == "MissingEmail"), Is.True);
    }

    [Test]
    public async Task LoginGoogleOauth_WhenEmailWhitespace_ReturnsError()
    {
        var principal = CreateGooglePrincipal(email: "   ", googleId: "gid");

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Errors!.Any(e => e.Code == "MissingEmail"), Is.True);
    }

    [Test]
    public async Task LoginGoogleOauth_WhenGoogleIdMissing_ReturnsError()
    {
        var principal = CreateGooglePrincipal(email: "g@example.com", googleId: null);

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Errors!.Any(e => e.Code == "MissingGoogleId"), Is.True);
    }

    [Test]
    public async Task LoginGoogleOauth_WhenExistingGoogleLogin_ReturnsTokens()
    {
        var email = "google@example.com";
        var googleId = "gid-1";
        var user = CreateUser(id: "oauth-1", email: email);
        user.IsOAuth = true;

        var principal = CreateGooglePrincipal(email, googleId);

        _userManagerMock
            .Setup(x => x.FindByLoginAsync("Google", googleId))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "user" });

        SetupJwt(user, "jwt-google", "refresh-google");

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Errors, Is.Null);
        Assert.That(result.Response, Is.Not.Null);
        Assert.That(result.Response!.jwt, Is.EqualTo("jwt-google"));
        Assert.That(result.Response.refreshToken, Is.EqualTo("refresh-google"));
        Assert.That(result.Response.email, Is.EqualTo(email));
        Assert.That(result.Response.userRole, Is.EqualTo("user"));

        // Nie tworzy użytkownika ani loginu
        _userManagerMock.Verify(x => x.CreateAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<UserLoginInfo>()), Times.Never);
    }

    [Test]
    public async Task LoginGoogleOauth_WhenUserExistsByEmail_LinksGoogleLogin()
    {
        var email = "existing@example.com";
        var googleId = "gid-link";
        var user = CreateUser(id: "u-link", email: email);

        var principal = CreateGooglePrincipal(email, googleId);

        _userManagerMock
            .Setup(x => x.FindByLoginAsync("Google", googleId))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.AddLoginAsync(user, It.Is<UserLoginInfo>(l =>
                l.LoginProvider == "Google" && l.ProviderKey == googleId)))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "user" });

        SetupJwt(user, "jwt-link", "refresh-link");

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Response, Is.Not.Null);
        Assert.That(result.Response!.jwt, Is.EqualTo("jwt-link"));
        _userManagerMock.Verify(x => x.CreateAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.AddLoginAsync(user, It.IsAny<UserLoginInfo>()), Times.Once);
    }

    [Test]
    public async Task LoginGoogleOauth_WhenNewUser_CreatesUserAddsRoleAndLogin()
    {
        var email = "brandnew@example.com";
        var googleId = "gid-new";
        var principal = CreateGooglePrincipal(email, googleId);

        ApplicationUser? created = null;

        _userManagerMock
            .Setup(x => x.FindByLoginAsync("Google", googleId))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success)
            .Callback<ApplicationUser>(u =>
            {
                u.Id = "new-oauth-id";
                created = u;
            });

        _userManagerMock
            .Setup(x => x.IsInRoleAsync(It.IsAny<ApplicationUser>(), "user"))
            .ReturnsAsync(false);

        _userManagerMock
            .Setup(x => x.IsInRoleAsync(It.IsAny<ApplicationUser>(), "admin"))
            .ReturnsAsync(false);

        _userManagerMock
            .Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "user"))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<UserLoginInfo>()))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { "user" });

        _jwtServiceMock
            .Setup(x => x.GenerateToken(It.IsAny<ApplicationUser>()))
            .ReturnsAsync("jwt-new-oauth");

        _jwtServiceMock
            .Setup(x => x.GenerateRefreshToken())
            .Returns("refresh-new-oauth");

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Errors, Is.Null);
        Assert.That(result.Response, Is.Not.Null);
        Assert.That(result.Response!.jwt, Is.EqualTo("jwt-new-oauth"));
        Assert.That(result.Response.refreshToken, Is.EqualTo("refresh-new-oauth"));
        Assert.That(result.Response.email, Is.EqualTo(email));

        _userManagerMock.Verify(x => x.CreateAsync(
            It.Is<ApplicationUser>(u =>
                u.Email == email &&
                u.UserName == email &&
                u.EmailConfirmed == true &&
                u.IsOAuth == true)), Times.Once);

        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "user"), Times.Once);
        _userManagerMock.Verify(x => x.AddLoginAsync(It.IsAny<ApplicationUser>(), It.IsAny<UserLoginInfo>()), Times.Once);

        Assert.That(await _context.RefreshTokens.CountAsync(), Is.EqualTo(1));
    }

    [Test]
    public async Task LoginGoogleOauth_WhenCreateUserFails_ReturnsErrors()
    {
        var principal = CreateGooglePrincipal("fail@example.com", "gid-fail");

        _userManagerMock
            .Setup(x => x.FindByLoginAsync("Google", "gid-fail"))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.FindByEmailAsync("fail@example.com"))
            .ReturnsAsync((ApplicationUser?)null);

        var errors = new[]
        {
            new IdentityError { Code = "DuplicateUserName", Description = "Already taken" }
        };

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Failed(errors));

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Response, Is.Null);
        Assert.That(result.Errors!.Any(e => e.Code == "DuplicateUserName"), Is.True);
    }

    [Test]
    public async Task LoginGoogleOauth_WhenAddLoginFails_ReturnsErrors()
    {
        var email = "linkfail@example.com";
        var user = CreateUser(id: "u-fail", email: email);
        var principal = CreateGooglePrincipal(email, "gid-addfail");

        _userManagerMock
            .Setup(x => x.FindByLoginAsync("Google", "gid-addfail"))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        var errors = new[]
        {
            new IdentityError { Code = "LoginAlreadyAssociated", Description = "Already linked" }
        };

        _userManagerMock
            .Setup(x => x.AddLoginAsync(user, It.IsAny<UserLoginInfo>()))
            .ReturnsAsync(IdentityResult.Failed(errors));

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Response, Is.Null);
        Assert.That(result.Errors!.Any(e => e.Code == "LoginAlreadyAssociated"), Is.True);
    }

    [Test]
    public async Task LoginGoogleOauth_WhenValidRefreshExists_ReusesIt()
    {
        var email = "reuse@example.com";
        var googleId = "gid-reuse";
        var user = CreateUser(id: "u-reuse", email: email);

        var principal = CreateGooglePrincipal(email, googleId);

        _userManagerMock
            .Setup(x => x.FindByLoginAsync("Google", googleId))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "user" });

        SetupJwt(user, "jwt", "unused");

        _context.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            Token = "existing-oauth-refresh",
            Expires = DateTime.UtcNow.AddDays(15),
            Created = DateTime.UtcNow,
            Revoked = null
        });
        await _context.SaveChangesAsync();

        var result = await _service.LoginGoogleOauth(principal);

        Assert.That(result.Response!.refreshToken, Is.EqualTo("existing-oauth-refresh"));
        _jwtServiceMock.Verify(x => x.GenerateRefreshToken(), Times.Never);
    }
}