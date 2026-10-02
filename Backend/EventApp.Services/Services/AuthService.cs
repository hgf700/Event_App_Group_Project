using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Services.Interface;
using EventApp.Services.Services.model;
using EventApp.Services.Services.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Superpower.Model;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace EventApp.Services.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthService> _logger;
    private readonly ApplicationDbContext _context;

    public AuthService(UserManager<ApplicationUser> userManager,
        IJwtService jwtService,
        ILogger<AuthService> logger,
        ApplicationDbContext dbContext
        )
    {
        _userManager = userManager;
        _jwtService = jwtService;
        _logger = logger;
        _context = dbContext;
    }

    public async Task<NormalRegisterResult> RegisterNormalAsync(postCreateUserNormDto dto)
    {
        var existingUser = await _userManager.FindByEmailAsync(dto.email);

        if (existingUser != null)
        {
            return new NormalRegisterResult
            {
                UserAlreadyExists = true
            };
        }

        var user = new ApplicationUser
        {
            UserName = dto.email,
            Email = dto.email,
            IsOAuth = false,
        };

        var result = await _userManager.CreateAsync(user, dto.password);

        if (!result.Succeeded)
        {
            return new NormalRegisterResult
            {
                Errors = result.Errors
            };
        }

        var role = await _userManager.AddToRoleAsync(user, "User");

        var roles = await _userManager.GetRolesAsync(user);

        var token = _jwtService.GenerateToken(user);

        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = _jwtService.GenerateRefreshToken(),
            Expires = DateTime.UtcNow.AddDays(30),
            Created = DateTime.UtcNow
        };

        _context.RefreshTokens.Add(refreshToken);
            
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "User successfully registered {Email}",
            dto.email);

        return new NormalRegisterResult
        {
            Response = new authResponseDto
            {
                jwt = token,
                email = dto.email,
                userRole = roles.FirstOrDefault() ?? ""
            },
        };
    }

    public async Task<NormalLoginResult> LoginNormalAsync(postLoginUserNormDto dto)
    {
        var existingUser = await _userManager.FindByEmailAsync(dto.email);

        if (existingUser == null)
        {
            return new NormalLoginResult
            {
                IncorrectUserCredentials = true
            };
        }

        var validPassword = await _userManager.CheckPasswordAsync(existingUser, dto.password);

        if (!validPassword)
        {
            return new NormalLoginResult
            {
                IncorrectUserCredentials = true
            };
        }

        var isUser = await _userManager.IsInRoleAsync(existingUser, "User");
        var isAdmin = await _userManager.IsInRoleAsync(existingUser, "Admin");

        if (!isUser && !isAdmin)
        {
            await _userManager.AddToRoleAsync(existingUser, "User");
        }

        var roles = await _userManager.GetRolesAsync(existingUser);

        var token = _jwtService.GenerateToken(existingUser);

        var existsRefresh = await _context.RefreshTokens
             .AnyAsync(b =>
                 b.UserId == existingUser.Id &&
                 b.Expires >= DateTime.UtcNow &&
                 b.Revoked == null);

        if (!existsRefresh)
        {
            var refreshToken = new RefreshToken
            {
                UserId = existingUser.Id,
                Token = _jwtService.GenerateRefreshToken(),
                Expires = DateTime.UtcNow.AddDays(30),
                Created = DateTime.UtcNow,
            };

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();
        }

        return new NormalLoginResult
        {
            Response = new authResponseDto
            {
                jwt = token,
                email = dto.email,
                userRole = roles.FirstOrDefault() ?? ""
            },
        };
    }

    public async Task<GoogleLoginResult> LoginGoogleOauth(ClaimsPrincipal principal)
    {
        var email = principal.FindFirstValue(ClaimTypes.Email);
        var googleId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrWhiteSpace(email))
        {
            return new GoogleLoginResult
            {
                Errors = new[]
                {
                    new IdentityError
                    {
                        Code = "MissingEmail",
                        Description = "Missing email from Google."
                    }
                }
            };
        }

        if (string.IsNullOrWhiteSpace(googleId))
        {
            return new GoogleLoginResult
            {
                Errors = new[]
                {
                    new IdentityError
                    {
                        Code = "MissingGoogleId",
                        Description = "Missing Google ID."
                    }
                }
            };
        }

        // 1. Najpierw szukamy użytkownika po Google login
        var user = await _userManager.FindByLoginAsync(
            "Google",
            googleId);

        // 2. Nie ma powiązania Google -> sprawdzamy email
        if (user == null)
        {
            user = await _userManager.FindByEmailAsync(email);

            // 3. Nie ma użytkownika -> tworzymy
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    IsOAuth = true
                };

                var createResult = await _userManager.CreateAsync(user);

                if (!createResult.Succeeded)
                {
                    return new GoogleLoginResult
                    {
                        Errors = createResult.Errors
                    };
                }

                var isUser = await _userManager.IsInRoleAsync(user, "User");
                var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");

                if (!isUser && !isAdmin)
                {
                    await _userManager.AddToRoleAsync(user, "User");
                }

                _logger.LogInformation(
                    "OAuth user created successfully. UserId: {UserId}",
                    user.Id);
            }

            // 4. Dodajemy Google login do istniejącego/nowego użytkownika
            var loginInfo = new UserLoginInfo(
                "Google",
                googleId,
                "Google");

            var addLoginResult = await _userManager.AddLoginAsync(
                user,
                loginInfo);

            if (!addLoginResult.Succeeded)
            {
                return new GoogleLoginResult
                {
                    Errors = addLoginResult.Errors
                };
            }
        }
        
        var roles = await _userManager.GetRolesAsync(user);

        // 5. Generujemy JWT
        var token = _jwtService.GenerateToken(user);

        // 6. Sprawdzamy refresh token
        var existsRefresh = await _context.RefreshTokens
            .AnyAsync(b =>
                b.UserId == user.Id &&
                b.Expires >= DateTime.UtcNow &&
                b.Revoked == null);

        // 7. Tworzymy refresh token, jeżeli użytkownik go nie ma
        if (!existsRefresh)
        {
            var refreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = _jwtService.GenerateRefreshToken(),
                Expires = DateTime.UtcNow.AddDays(30),
                Created = DateTime.UtcNow
            };

            _context.RefreshTokens.Add(refreshToken);

            await _context.SaveChangesAsync();
        }

        _logger.LogInformation(
            "User {UserId} logged in with Google OAuth",
            user.Id);

        return new GoogleLoginResult
        {
            Response = new authResponseDto
            {
                jwt = token,
                email = email,
                userRole = roles.FirstOrDefault() ?? ""
            },
        };
    }
}
