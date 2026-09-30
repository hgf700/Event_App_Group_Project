using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Services.model;
using EventApp.Services.Services.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Interfaces;

public interface IPaymentService
{
    Task<BuyTicketResult> BuyTicketAsync(string userId, int id);
    Task<PaymentResult> PaymentSuccess(string userId, int id);
}
