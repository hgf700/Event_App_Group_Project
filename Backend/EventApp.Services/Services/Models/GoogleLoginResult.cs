using EventApp.Services.Dto.RelAuth;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Models;

public class GoogleLoginResult
{
    public authResponseDto? Response { get; set; }
    public string? Email { get; set; }
    public string UserRole { get; set; } = "";
    public IEnumerable<IdentityError>? Errors { get; set; }
}