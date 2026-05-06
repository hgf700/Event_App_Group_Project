using Backend.Db;
using Backend.Identity;
using Backend.Models.Model;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Stripe;
using Stripe.Checkout;
using System.Security.Claims;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class PaymentsController
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private string YOUR_DOMAIN = "";

    public PaymentsController(UserManager<ApplicationUser> userManager,
        ApplicationDbContext context
        )
    {
        _context = context;
        _userManager = userManager;
    }

    //[HttpPost("buy-ticket/{id}")]
    //public async Task<ActionResult> BuyTicket(int id)
    //{
    //    if (!ModelState.IsValid)
    //        return BadRequest(ModelState);

    //    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    //    if (userId == null)
    //        return Unauthorized();

    //    var ev = await _context.Events.FindAsync(id);
    //    if (ev == null)
    //        return NotFound();

    //    StripeConfiguration.ApiKey = Environment.GetEnvironmentVariable("STRIP_SEC_KEY");

    //    var options = new SessionCreateOptions
    //    {
    //        LineItems = new List<SessionLineItemOptions>
    //            {
    //                new SessionLineItemOptions
    //                {
    //                    PriceData = new SessionLineItemPriceDataOptions
    //                    {
    //                        Currency = "pln",
    //                        UnitAmount = 1000,
    //                        ProductData = new SessionLineItemPriceDataProductDataOptions
    //                        {
    //                            Name = "Bilet na wydarzenie",
    //                        },
    //                    },
    //                    Quantity = 1,
    //                },
    //            },

    //        Mode = "payment",
    //        SuccessUrl = $"{YOUR_DOMAIN}/Event/PaymentSuccess?id={id}",
    //        CancelUrl = $"{YOUR_DOMAIN}/Event/PaymentFailed",
    //    };
    //    var service = new SessionService();
    //    Session session = service.Create(options);

    //    return Redirect(session.Url); // przekierowuje do strony Stripe Checkout
    //}
}
