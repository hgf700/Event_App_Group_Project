using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Interfaces;
using EventApp.Services.Services.Interfaces;
using EventApp.Services.Services.model;
using EventApp.Services.Services.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services;

public class UserService : IUserService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthService> _logger;
    private readonly ApplicationDbContext _context;

    public UserService(UserManager<ApplicationUser> userManager,
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

    public async Task<EditUserPasswordResult> EditUserPasswordAsync(string userId, postEditUserPasswordDto dto)
    {
        var user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return new EditUserPasswordResult
            {
                UserNotFound = true
            };
        }

        var currentPasswordValid = await _userManager.CheckPasswordAsync(
            user,
            dto.oldPassword);

        if (!currentPasswordValid)
        {
            return new EditUserPasswordResult
            {
                IncorrectPassword = true
            };
        }

        var passwordResult = await _userManager.ChangePasswordAsync(
            user,
            dto.oldPassword,
            dto.newPassword);

        if (!passwordResult.Succeeded)
        {
            return new EditUserPasswordResult
            {
                Errors = passwordResult.Errors.ToArray()
            };
        }

        return new EditUserPasswordResult();
    }

    public async Task<EditUserEmailResult> EditUserEmailAsync(string userId, string newEmail)
    {
        var user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return new EditUserEmailResult
            {
                UserNotFound = true
            };
        }

        var emailExists = await _userManager.FindByEmailAsync(newEmail);

        if (emailExists == null)
        {
            return new EditUserEmailResult
            {
                IncorrectEmail = true
            };
        }

        user.Email = newEmail;
        user.UserName = newEmail;

        var result = await _userManager.UpdateAsync(user);

        if (!result.Succeeded)
        {
            return new EditUserEmailResult
            {
                Errors = result.Errors.ToArray()
            };
        }

        var token = await _jwtService.GenerateToken(user);

        return new EditUserEmailResult
        {
            Response = new authResponseDto
            {
                jwt = token,
                email = newEmail,
            }
        };
    }
}
