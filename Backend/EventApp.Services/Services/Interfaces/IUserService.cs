using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Services.model;
using EventApp.Services.Services.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Interfaces;

public interface IUserService
{
    Task<EditUserPasswordResult> EditUserPasswordAsync(string userId, postEditUserPasswordDto dto);
    Task<EditUserEmailResult> EditUserEmailAsync(string userId, string newEmail);
}
