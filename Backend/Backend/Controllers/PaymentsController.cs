using EventApp.Infrastructure.Db;
using EventApp.Services.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Stripe;
using Stripe.Checkout;
using System.Security.Claims;

namespace Backend.Controllers;

[ApiController]
[Authorize(Roles = "admin,user")]
[Route("api/v1/[controller]")]
public class PaymentsController : ControllerBase
{
    private readonly ILogger<PaymentsController> _logger;
    private readonly IPaymentService _paymentService;
    private readonly ApplicationDbContext _context;

    public PaymentsController(
        ILogger<PaymentsController> logger,
        IPaymentService paymentService,
        ApplicationDbContext context)
    {
        _logger = logger;
        _paymentService = paymentService;
        _context = context;
    }

    // =========================================================
    // BUY TICKET
    // =========================================================

    [HttpPost("buy-ticket/{id:int:min(0)}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> BuyTicket(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId == null)
            return Unauthorized();

        try
        {
            var result = await _paymentService.BuyTicketAsync(userId, id);

            if (result.EventNotFound)
                return NotFound();

            if (result.AlreadyBoughtTicket)
                return Conflict("User already owns this ticket");

            if (result.PaymentAlreadyPending)
                return Conflict("Payment for this ticket is already pending");

            if (result.Errors != null)
                return BadRequest(result.Errors);

            _logger.LogInformation(
                "Stripe checkout created for UserId: {UserId}, EventId: {EventId}",
                userId,
                id);

            return Ok(new
            {
                url = result.Response
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Error while buying ticket for UserId: {UserId}, EventId: {EventId}",
                userId,
                id);

            return StatusCode(
                StatusCodes.Status500InternalServerError,
                "Internal server error");
        }
    }

    // =========================================================
    // STRIPE WEBHOOK
    // =========================================================

    [AllowAnonymous]
    [HttpPost("stripe-webhook")]
    public async Task<IActionResult> StripeWebhook()
    {
        var json = await new StreamReader(Request.Body).ReadToEndAsync();

        var webhookSecret = Environment.GetEnvironmentVariable("STRIPE_WEBHOOK_SECRET");

        if (string.IsNullOrWhiteSpace(webhookSecret))
        {
            _logger.LogError("Stripe webhook secret is missing");

            return BadRequest();
        }

        var stripeSignature = Request.Headers["Stripe-Signature"];

        if (string.IsNullOrWhiteSpace(stripeSignature))
        {
            _logger.LogWarning("Stripe-Signature header is missing");

            return BadRequest();
        }

        Event stripeEvent;

        try
        {
            stripeEvent = EventUtility.ConstructEvent(
                    json,
                    stripeSignature,
                    webhookSecret);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Invalid Stripe webhook");

            return BadRequest();
        }

        switch (stripeEvent.Type)
        {
            case "checkout.session.completed":

                var session = stripeEvent.Data.Object as Stripe.Checkout.Session;

                if (session == null)
                    return BadRequest();

                await _paymentService.HandleSuccessfulPaymentAsync(session);

                break;

            case "checkout.session.expired":

                var expiredSession = stripeEvent.Data.Object as Stripe.Checkout.Session;

                if (expiredSession == null)
                    return BadRequest();

                await _paymentService.HandleExpiredPaymentAsync(expiredSession);

                break;

            default:

                _logger.LogInformation(
                    "Unhandled Stripe event type: {EventType}",
                    stripeEvent.Type);

                break;
        }

        return Ok();
    }

    // =========================================================
    // PAYMENT STATUS
    // =========================================================

    [Authorize]
    [HttpGet("status/{id:int}")]
    public async Task<IActionResult> GetPaymentStatus(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId == null)
            return Unauthorized();

        var userEvent = await _context.UserEvents
                .AsNoTracking()
                .FirstOrDefaultAsync(x => x.Id == id && x.UserId == userId);

        if (userEvent == null)
            return NotFound();

        return Ok(new
        {
            id = userEvent.Id,
            state = userEvent.State.ToString(),
            createdAt = userEvent.CreatedAt,
            paidAt = userEvent.PaidAt
        });
    }
}