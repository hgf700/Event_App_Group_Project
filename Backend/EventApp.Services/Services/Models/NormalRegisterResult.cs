using EventApp.Services.Dto.RelAuth;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.model;

public class NormalRegisterResult
{
    public AuthResponseDto? Response { get; init; }
    public bool UserAlreadyExists { get; init; }
    public string UserRole { get; set; } = "";
    public IEnumerable<IdentityError>? Errors { get; set; }
}
