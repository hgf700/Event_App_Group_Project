using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Services;
using EventApp.Services.Services.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TestServices.ServiceTest;

[TestFixture]
public class UserTest
{
    private Mock<UserManager<ApplicationUser>> _userManagerMock = null!;
    private Mock<IJwtService> _jwtServiceMock = null!;
    private Mock<ILogger<AuthService>> _loggerMock = null!;
    private ApplicationDbContext _context = null!;
    private UserService _service = null!;

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

        _service = new UserService(
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
            Email = email
        };
    }

    // ============================================================
    // EditUserPasswordAsync
    // ============================================================

    [Test]
    public async Task EditUserPasswordAsync_WhenUserNotFound_ReturnsUserNotFound()
    {
        var dto = new postEditUserPasswordDto
        {
            oldPassword = "OldPass1!",
            newPassword = "NewPass1!"
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync("missing-id"))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _service.EditUserPasswordAsync("missing-id", dto);

        Assert.That(result.UserNotFound, Is.True);
        Assert.That(result.IncorrectPassword, Is.False);
        Assert.That(result.Errors, Is.Null);
    }

    [Test]
    public async Task EditUserPasswordAsync_WhenOldPasswordInvalid_ReturnsIncorrectPassword()
    {
        var user = CreateUser();
        var dto = new postEditUserPasswordDto
        {
            oldPassword = "WrongOld!",
            newPassword = "NewPass1!"
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.CheckPasswordAsync(user, dto.oldPassword))
            .ReturnsAsync(false);

        var result = await _service.EditUserPasswordAsync(user.Id, dto);

        Assert.That(result.IncorrectPassword, Is.True);
        Assert.That(result.UserNotFound, Is.False);
        Assert.That(result.Errors, Is.Null);

        _userManagerMock.Verify(
            x => x.ChangePasswordAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    [Test]
    public async Task EditUserPasswordAsync_WhenChangePasswordFails_ReturnsErrors()
    {
        var user = CreateUser();
        var dto = new postEditUserPasswordDto
        {
            oldPassword = "OldPass1!",
            newPassword = "weak"
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.CheckPasswordAsync(user, dto.oldPassword))
            .ReturnsAsync(true);

        var identityErrors = new[]
        {
            new IdentityError
            {
                Code = "PasswordTooShort",
                Description = "Passwords must be at least 6 characters."
            }
        };

        _userManagerMock
            .Setup(x => x.ChangePasswordAsync(user, dto.oldPassword, dto.newPassword))
            .ReturnsAsync(IdentityResult.Failed(identityErrors));

        var result = await _service.EditUserPasswordAsync(user.Id, dto);

        Assert.That(result.UserNotFound, Is.False);
        Assert.That(result.IncorrectPassword, Is.False);
        Assert.That(result.Errors, Is.Not.Null);
        Assert.That(result.Errors!.Any(e => e.Code == "PasswordTooShort"), Is.True);
    }

    [Test]
    public async Task EditUserPasswordAsync_WhenSuccess_ReturnsEmptyResult()
    {
        var user = CreateUser();
        var dto = new postEditUserPasswordDto
        {
            oldPassword = "OldPass1!",
            newPassword = "NewPass1!"
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.CheckPasswordAsync(user, dto.oldPassword))
            .ReturnsAsync(true);

        _userManagerMock
            .Setup(x => x.ChangePasswordAsync(user, dto.oldPassword, dto.newPassword))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _service.EditUserPasswordAsync(user.Id, dto);

        Assert.That(result.UserNotFound, Is.False);
        Assert.That(result.IncorrectPassword, Is.False);
        Assert.That(result.Errors, Is.Null);

        _userManagerMock.Verify(
            x => x.ChangePasswordAsync(user, dto.oldPassword, dto.newPassword),
            Times.Once);
    }

    // ============================================================
    // EditUserEmailAsync
    // (testy zgodne z OBECNĄ logiką kodu)
    // ============================================================

    [Test]
    public async Task EditUserEmailAsync_WhenUserNotFound_ReturnsUserNotFound()
    {
        _userManagerMock
            .Setup(x => x.FindByIdAsync("missing"))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _service.EditUserEmailAsync("missing", "new@example.com");

        Assert.That(result.UserNotFound, Is.True);
        Assert.That(result.IncorrectEmail, Is.False);
        Assert.That(result.Response, Is.Null);
        Assert.That(result.Errors, Is.Null);
    }

    [Test]
    public async Task EditUserEmailAsync_WhenNewEmailNotFoundInSystem_ReturnsIncorrectEmail()
    {
        // Obecna logika: FindByEmailAsync == null → IncorrectEmail
        var user = CreateUser();

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.FindByEmailAsync("brand-new@example.com"))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _service.EditUserEmailAsync(user.Id, "brand-new@example.com");

        Assert.That(result.IncorrectEmail, Is.True);
        Assert.That(result.UserNotFound, Is.False);
        Assert.That(result.Response, Is.Null);

        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Test]
    public async Task EditUserEmailAsync_WhenEmailExistsAndUpdateFails_ReturnsErrors()
    {
        var user = CreateUser(id: "user-1", email: "old@example.com");
        var otherUserWithEmail = CreateUser(id: "user-2", email: "taken@example.com");

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        // Według obecnego kodu: email MUSI istnieć, żeby pójść dalej
        _userManagerMock
            .Setup(x => x.FindByEmailAsync("taken@example.com"))
            .ReturnsAsync(otherUserWithEmail);

        var identityErrors = new[]
        {
            new IdentityError
            {
                Code = "DuplicateUserName",
                Description = "Username already taken."
            }
        };

        _userManagerMock
            .Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Failed(identityErrors));

        var result = await _service.EditUserEmailAsync(user.Id, "taken@example.com");

        Assert.That(result.Errors, Is.Not.Null);
        Assert.That(result.Errors!.Any(e => e.Code == "DuplicateUserName"), Is.True);
        Assert.That(result.Response, Is.Null);
    }

    [Test]
    public async Task EditUserEmailAsync_WhenEmailExistsAndUpdateSucceeds_ReturnsJwt()
    {
        var user = CreateUser(id: "user-1", email: "old@example.com");
        // Obecna logika wymaga, żeby newEmail już istniał w systemie
        var emailOwner = CreateUser(id: "user-2", email: "existing@example.com");

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.FindByEmailAsync("existing@example.com"))
            .ReturnsAsync(emailOwner);

        _userManagerMock
            .Setup(x => x.UpdateAsync(It.Is<ApplicationUser>(u =>
                u.Id == user.Id &&
                u.Email == "existing@example.com" &&
                u.UserName == "existing@example.com")))
            .ReturnsAsync(IdentityResult.Success);

        _jwtServiceMock
            .Setup(x => x.GenerateToken(It.IsAny<ApplicationUser>()))
            .ReturnsAsync("new-jwt-token");

        var result = await _service.EditUserEmailAsync(user.Id, "existing@example.com");

        Assert.That(result.UserNotFound, Is.False);
        Assert.That(result.IncorrectEmail, Is.False);
        Assert.That(result.Errors, Is.Null);
        Assert.That(result.Response, Is.Not.Null);
        Assert.That(result.Response!.jwt, Is.EqualTo("new-jwt-token"));
        Assert.That(result.Response.email, Is.EqualTo("existing@example.com"));

        _userManagerMock.Verify(
            x => x.UpdateAsync(It.Is<ApplicationUser>(u =>
                u.Email == "existing@example.com" &&
                u.UserName == "existing@example.com")),
            Times.Once);

        _jwtServiceMock.Verify(
            x => x.GenerateToken(It.IsAny<ApplicationUser>()),
            Times.Once);
    }
}