using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Models;

public class EditUserPasswordResult
{
    public bool UserNotFound { get; set; }

    public bool IncorrectPassword { get; set; }

    public IdentityError[]? Errors { get; set; }
}
