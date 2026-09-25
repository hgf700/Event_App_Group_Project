using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Services.Interface;
using EventApp.Services.Services.model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthService> _logger;
    private readonly ApplicationDbContext _dbContext;

    public AuthService(UserManager<ApplicationUser> userManager,
        IJwtService jwtService,
        ILogger<AuthService> logger,
        ApplicationDbContext dbContext
        )
    {
        _userManager = userManager;
        _jwtService = jwtService;
        _logger = logger;
        _dbContext = dbContext;
    }

    public async Task<RegisterResult> RegisterNormalAsync(postCreateUserNormDto dto)
    {
        var existingUser = await _userManager.FindByEmailAsync(dto.email);

        if (existingUser != null)
        {
            return new RegisterResult
            {
                UserAlreadyExists = true
            };
        }

        var user = new ApplicationUser
        {
            UserName = dto.email,
            Email = dto.email,
            IsOAuth = false
        };

        var result = await _userManager.CreateAsync(user, dto.password);

        if (!result.Succeeded)
        {
            return new RegisterResult
            {
                Errors = result.Errors
            };
        }

        var token = _jwtService.GenerateToken(user);

        var existsRefresh = await _dbContext.RefreshTokens
            .AnyAsync(b =>
                b.UserId == user.Id &&
                b.Expires >= DateTime.UtcNow &&
                b.Revoked == null);

        if (!existsRefresh)
        {
            var refreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = _jwtService.GenerateRefreshToken(),
                Expires = DateTime.UtcNow.AddDays(30),
                Created = DateTime.UtcNow
            };

            _dbContext.RefreshTokens.Add(refreshToken);
            await _dbContext.SaveChangesAsync();
        }

        _logger.LogInformation(
            "User successfully registered {Email}",
            dto.email);

        return new RegisterResult
        {
            Response = new AuthResponseDto
            {
                jwt = token
            }
        };
    }
}
