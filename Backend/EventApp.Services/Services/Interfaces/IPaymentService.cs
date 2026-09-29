using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Services.model;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Services.Interfaces;

public interface IPaymentService
{
    Task BuyTicket();
    Task PaymentSuccess();
}
