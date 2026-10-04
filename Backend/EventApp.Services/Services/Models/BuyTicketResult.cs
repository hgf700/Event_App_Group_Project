using EventApp.Services.Dto.RelAuth;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Models;

public class BuyTicketResult
{
    public bool EventNotFound { get; set; }
    public bool PaymentAlreadyPending { get; set; }
    public bool AlreadyBoughtTicket { get; set; }
    public string? Response { get; set; }
    public int? UserEventId { get; set; }
    public IEnumerable<IdentityError>? Errors { get; set; }
}
