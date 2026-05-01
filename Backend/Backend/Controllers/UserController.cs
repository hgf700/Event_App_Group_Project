using Backend.Db;
using Backend.Identity;
using Backend.Models.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Stripe;

namespace Backend.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public UserController(UserManager<ApplicationUser> userManager, ApplicationDbContext context)
    {
        _userManager = userManager;
        _context = context;
    }

    [HttpGet]
    public async Task<ActionResult> Account()
    {
        var user = await _userManager.GetUserAsync(User);
        return Ok(user);
    }

    [HttpGet]
    public async Task<IActionResult> MyEvents()
    {
        var user = await _userManager.GetUserAsync(User);
        var events = await _context.UserEvents
            .Include(ue => ue.Event)
            .Where(ue => ue.UserId == user.Id)
            .ToListAsync();

        return Ok(events);
    }

    //[HttpPost]
    //public async Task<IActionResult> Edit()
    //{
    //    var user = await _userManager.GetUserAsync(User);

    //    if (user == null)
    //        return NotFound();

    //    var model = new EditUserViewModel
    //    {
    //        Email = user.Email,
    //        PhoneNumber = user.PhoneNumber
    //    };

    //    return Ok(model);
    //}

}
