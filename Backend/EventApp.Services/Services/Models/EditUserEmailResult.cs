using EventApp.Services.Dto.RelAuth;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Models;

public class EditUserEmailResult
{
    public AuthResponseDto? Response { get; init; }

    public bool UserNotFound { get; set; }

    public bool IncorrectEmail { get; set; }

    public IdentityError[]? Errors { get; set; }
}
