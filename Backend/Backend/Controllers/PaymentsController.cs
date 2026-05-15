using Backend.Db;
using Backend.Identity;
using Backend.Models.Model;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Stripe;
using Stripe.Checkout;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class PaymentsController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly string YOUR_DOMAIN = "http://localhost:4200";
    private readonly ILogger<PaymentsController> _logger;

    public PaymentsController(UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        ILogger<PaymentsController> logger
        )
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpPost("buy-ticket/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> BuyTicket(int id)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        var ev = await _context.Events.FindAsync(id);
        if (ev == null)
            return NotFound();

        var alreadyBought = await _context.UserEvents
            .AnyAsync(x => x.UserId == userId && x.EventId == id);

        if (alreadyBought)
            return BadRequest("User already owns this ticket");

        try
        {
            StripeConfiguration.ApiKey = Environment.GetEnvironmentVariable("STRIP_SEC_KEY");

            if (string.IsNullOrWhiteSpace(StripeConfiguration.ApiKey))
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "STRIPE_SECRET_KEY is missing");
            }

            var options = new SessionCreateOptions
            {
                LineItems = new List<SessionLineItemOptions>
                {
                    new SessionLineItemOptions
                    {
                        PriceData = new SessionLineItemPriceDataOptions
                        {
                            Currency = "pln",
                            UnitAmount = 1000,
                            ProductData = new SessionLineItemPriceDataProductDataOptions
                            {
                                Name = "Bilet na wydarzenie",
                            },
                        },
                        Quantity = 1,
                    },
                },

                Mode = "payment",
                SuccessUrl = $"{YOUR_DOMAIN}/payment-success?id={id}",
                CancelUrl = $"{YOUR_DOMAIN}/payment-failed",
            };
            var service = new SessionService();
            Session session = service.Create(options);

            _logger.LogInformation("User successfully bought ticket UserId: {UserId}", userId);

            return Ok(new { url = session.Url });
        }
        catch (Exception ex) {
            Console.WriteLine(ex);
            _logger.LogError(ex, "Error while buying ticket for UserId: {UserId}", userId);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
    
}
