using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace TestServices.Helper;

public class EventAppFactory : WebApplicationFactory<Program>
{
    private const string DatabaseName = "EventIntegrationTests";

    public EventAppFactory()
    {
        Environment.SetEnvironmentVariable("GOOGLE_CLIENT_ID", "test-client-id");
        Environment.SetEnvironmentVariable("GOOGLE_CLIENT_SECRET", "test-client-secret");
        Environment.SetEnvironmentVariable("JWT_SECRET", "test-jwt-secret-key-at-least-32-chars!!");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("IntegrationTest");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] =
                    "Host=localhost;Database=test;Username=test;Password=test"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            // Usuwamy wyłącznie rejestracje dotyczące ApplicationDbContext.
            services.RemoveAll<ApplicationDbContext>();
            services.RemoveAll<DbContextOptions<ApplicationDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<ApplicationDbContext>>();

            // Testowa baza InMemory.
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseInMemoryDatabase(DatabaseName));

            // Testowy schemat uwierzytelniania.
            services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                    options.DefaultChallengeScheme = TestAuthHandler.SchemeName;
                    options.DefaultScheme = TestAuthHandler.SchemeName;
                })
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(
                    TestAuthHandler.SchemeName,
                    _ => { });
        });
    }

    public async Task ResetDbAsync()
    {
        using var scope = Services.CreateScope();

        var db = scope.ServiceProvider
            .GetRequiredService<ApplicationDbContext>();

        await db.Database.EnsureCreatedAsync();

        db.Events.RemoveRange(db.Events);
        await db.SaveChangesAsync();
    }

    public async Task SeedAsync(params Event[] events)
    {
        using var scope = Services.CreateScope();

        var db = scope.ServiceProvider
            .GetRequiredService<ApplicationDbContext>();

        await db.Database.EnsureCreatedAsync();

        db.Events.RemoveRange(db.Events);
        await db.SaveChangesAsync();

        if (events.Length > 0)
        {
            db.Events.AddRange(events);
            await db.SaveChangesAsync();
        }
    }

    public async Task<ApplicationUser> CreateTestUserAsync(
        string email,
        string password,
        string? role = null)
    {
        using var scope = Services.CreateScope();

        var userManager = scope.ServiceProvider
            .GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            IsOAuth = false
        };

        var result = await userManager.CreateAsync(user, password);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                "Nie udało się utworzyć użytkownika testowego: " +
                string.Join("; ", result.Errors.Select(e => e.Description)));
        }

        if (!string.IsNullOrWhiteSpace(role))
        {
            var roleManager = scope.ServiceProvider
                .GetRequiredService<Microsoft.AspNetCore.Identity.RoleManager<Microsoft.AspNetCore.Identity.IdentityRole>>();

            if (!await roleManager.RoleExistsAsync(role))
            {
                var roleResult = await roleManager.CreateAsync(
                    new Microsoft.AspNetCore.Identity.IdentityRole(role));

                if (!roleResult.Succeeded)
                {
                    throw new InvalidOperationException(
                        "Nie udało się utworzyć roli testowej: " +
                        string.Join("; ",
                            roleResult.Errors.Select(e => e.Description)));
                }
            }

            var addRoleResult = await userManager.AddToRoleAsync(user, role);

            if (!addRoleResult.Succeeded)
            {
                throw new InvalidOperationException(
                    "Nie udało się przypisać roli testowej: " +
                    string.Join("; ",
                        addRoleResult.Errors.Select(e => e.Description)));
            }
        }

        return user;
    }
}

public class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "TestScheme";

    public TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var header))
        {
            return Task.FromResult(
                AuthenticateResult.Fail("Missing Authorization header"));
        }

        var value = header.ToString();

        if (!value.StartsWith("Test ", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(
                AuthenticateResult.Fail("Invalid scheme"));
        }

        var payload = value["Test ".Length..].Trim();
        var parts = payload.Split('|');

        var role = parts.ElementAtOrDefault(0) ?? "user";
        var userId = parts.ElementAtOrDefault(1) ?? "test-user-id";

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Name, userId),
            new Claim(ClaimTypes.Email, $"{userId}@test.com"),
            new Claim(ClaimTypes.Role, role)
        };

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}