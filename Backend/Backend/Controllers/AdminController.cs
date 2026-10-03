using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers;

[ApiController]
[Authorize(Roles = "admin")]
[Route("api/v1/[controller]")]
public class AdminController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;

    public AdminController(ApplicationDbContext context,
        UserManager<ApplicationUser> userManager
        )
    {
        _context = context;
        _userManager = userManager;
    }


}
