using Backend.Db;
using Backend.Identity;
using Backend.Models.Dto;
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

    public UserController(UserManager<ApplicationUser> userManager, 
        ApplicationDbContext context
        )
    {
        _userManager = userManager;
        _context = context;
    }

    [HttpPost("register-norm")]
    public async Task<ActionResult<postCreateUserDto>> RegisterUserNormal([FromBody] postCreateUserDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        if (dto.Password != dto.ConfirmPassword)
            return BadRequest("Passwords do not match");

        var existingUser = await _userManager.FindByEmailAsync(dto.Email);
        if (existingUser != null)
            return BadRequest("User already exists");

        var user = new ApplicationUser
        {
            UserName = dto.Email,
            Email = dto.Email,
            PasswordHash=dto.Password,
            IsOAuth = false
        };

        var result = await _userManager.CreateAsync(user, dto.Password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok(result);

    }

    //[HttpPost]
    //public async Task<ActionResult> RegisterUserOauth([FromBody] )
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
