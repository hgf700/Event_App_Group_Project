using EventApp.Services.Dto.RelAuth;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Models;

public class NormalLoginResult
{
    public AuthResponseDto? Response { get; init; }
    public bool IncorrectUserCredentials { get; init; }
}
