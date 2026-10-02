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
using QRCoder;
using QuestPDF.Fluent;
using System.Security.Claims;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class PaymentCallbackController : ControllerBase
{
    private readonly ILogger<PaymentCallbackController> _logger;
    private readonly IPaymentService _paymentService;


    public PaymentCallbackController(
        ILogger<PaymentCallbackController> logger,
        IPaymentService paymentService
        )
    {
        _logger = logger;
        _paymentService = paymentService;
    }

    [HttpPost("payment-success/{id:int:min(0)}")]
    //[Authorize]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult> PaymentSuccess(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        try
        {
            var result = await _paymentService.PaymentSuccess(userId, id);

            if (result.EventNotExists)
                return NotFound();

            if (result.EventAlreadyExists)
                return Conflict("Ticket already assigned");

            return Ok(new { success = true });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while buying ticket for user: {UserId}", userId);
            return StatusCode(StatusCodes.Status500InternalServerError, "Internal server error");
        }
    }

    [HttpPost("payment-failed")]
    //[Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult> PaymentFailed()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();

        return Ok();
    }
}
