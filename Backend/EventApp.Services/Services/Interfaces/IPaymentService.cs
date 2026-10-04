using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Services.model;
using EventApp.Services.Services.Models;
using Stripe.Checkout;

namespace EventApp.Services.Services.Interfaces;

public interface IPaymentService
{
    Task<BuyTicketResult> BuyTicketAsync(string userId, int id);

    Task HandleSuccessfulPaymentAsync(Session session);

    Task HandleExpiredPaymentAsync(Session session);
}