using Backend.Db;
using Backend.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers;

//[Authorize]
[ApiController]
[Route("api/v1/[controller]")]
public class UserController
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;

    public UserController(UserManager<ApplicationUser> userManager, 
        ApplicationDbContext context
        )
    {
        _userManager = userManager;
        _context = context;
    }

    //public async Task<IActionResult> Account()
    //{
    //    var user = await _userManager.GetUserAsync(User);
    //    return View(user);
    //}

    //public async Task<IActionResult> MyEvents()
    //{
    //    var user = await _userManager.GetUserAsync(User);
    //    var events = await _context.UserEvents
    //        .Include(ue => ue.Event)
    //        .Where(ue => ue.UserId == user.Id)
    //        .ToListAsync();

    //    return View(events);
    //}

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

    //    return View(model);
    //}


    //[HttpPost]
    //[ValidateAntiForgeryToken]
    //public async Task<IActionResult> Edit(EditUserViewModel model)
    //{
    //    if (!ModelState.IsValid)
    //        return View(model);

    //    var user = await _userManager.GetUserAsync(User);
    //    if (user == null)
    //        return NotFound();

    //    // Zmieniamy dane tylko jeśli coś się faktycznie zmienia
    //    if (user.Email != model.Email)
    //        user.Email = model.Email;

    //    if (user.PhoneNumber != model.PhoneNumber)
    //        user.PhoneNumber = model.PhoneNumber;

    //    var result = await _userManager.UpdateAsync(user);

    //    if (result.Succeeded)
    //    {
    //        TempData["StatusMessage"] = "Dane zostały zaktualizowane.";
    //        return RedirectToAction("Details");
    //    }

    //    foreach (var error in result.Errors)
    //        ModelState.AddModelError(string.Empty, error.Description);

    //    return View(model);
    //}
}
