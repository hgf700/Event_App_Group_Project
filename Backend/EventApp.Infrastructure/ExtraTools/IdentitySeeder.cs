using EventApp.Domain.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Infrastructure.ExtraTools;

public static class IdentitySeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        const string adminEmail = "admin";
        const string adminPassword = "admin";

        var roleManager =
            services.GetRequiredService<RoleManager<IdentityRole>>();

        var userManager =
            services.GetRequiredService<UserManager<ApplicationUser>>();

        // =========================
        // ROLES
        // =========================

        string[] roles =
        [
            "Admin",
            "User"
        ];

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                var result = await roleManager.CreateAsync(
                    new IdentityRole(role));

                if (!result.Succeeded)
                {
                    throw new Exception(
                        $"Nie udało się utworzyć roli {role}: " +
                        string.Join(", ",
                            result.Errors.Select(e => e.Description)));
                }

                Console.WriteLine($"Utworzono rolę: {role}");
            }
        }

        // =========================
        // ADMIN USER
        // =========================

        var admin = await userManager.FindByEmailAsync(adminEmail);

        if (admin == null)
        {
            admin = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(
                admin,
                adminPassword);

            if (!result.Succeeded)
            {
                throw new Exception(
                    "Nie udało się utworzyć administratora: " +
                    string.Join(", ",
                        result.Errors.Select(e => e.Description)));
            }

            Console.WriteLine($"Utworzono administratora: {adminEmail}");
        }

        // =========================
        // ADMIN ROLE
        // =========================

        if (!await userManager.IsInRoleAsync(admin, "Admin"))
        {
            var result = await userManager.AddToRoleAsync(
                admin,
                "Admin");

            if (!result.Succeeded)
            {
                throw new Exception(
                    "Nie udało się przypisać roli Admin: " +
                    string.Join(", ",
                        result.Errors.Select(e => e.Description)));
            }

            Console.WriteLine(
                $"Przypisano rolę Admin użytkownikowi {adminEmail}");
        }
    }
}