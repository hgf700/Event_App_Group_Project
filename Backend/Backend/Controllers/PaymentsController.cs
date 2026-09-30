using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Dto.RelEvent;
using EventApp.Services.Interfaces;
using EventApp.Services.Model;
using EventApp.Services.Services;
using EventApp.Services.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Stripe;
using Stripe.Checkout;
using Superpower.Model;
using System.Security.Claims;

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
    private readonly IPaymentService _paymentService;

    public PaymentsController(UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        ILogger<PaymentsController> logger,
        IPaymentService paymentService
        )
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
        _paymentService = paymentService;
    }

    [HttpPost("buy-ticket/{id:int:min(0)}")]
    //[Authorize]
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

            if(result.EventNotFound)
                return NotFound();

            if(result.AlreadyBoughtTicket)
                return Conflict("User already owns this ticket");

            if (result.Errors != null)
                return BadRequest(result.Errors);

            _logger.LogInformation("User successfully bought ticket UserId: {UserId}", userId);

            return Ok(new
            {
                checkoutUrl = result.Response
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while buying ticket for UserId: {UserId}", userId);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }
    
}
