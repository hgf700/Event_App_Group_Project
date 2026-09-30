using EventApp.Services.Dto.RelAuth;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Models;

public class PaymentResult
{
    public bool? EventExists { get; set; }
    public bool? EventAlreadyExists { get; set; }
    public bool? Success { get; set; }
    public IEnumerable<IdentityError>? Errors { get; set; }
}
