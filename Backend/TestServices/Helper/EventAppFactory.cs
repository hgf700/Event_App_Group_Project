using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace TestServices.Helper;

public class EventAppFactory : WebApplicationFactory<Program>
{
    public EventAppFactory()
    {
        // Zanim Build() – te same nazwy co w Program.cs
        Environment.SetEnvironmentVariable("GOOGLE_CLIENT_ID", "test-client-id");
        Environment.SetEnvironmentVariable("GOOGLE_CLIENT_SECRET", "test-client-secret");
        Environment.SetEnvironmentVariable("JWT_SECRET", "test-jwt-secret-key-at-least-32-chars!!");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development"); // albo "Testing" – bez znaczenia dla Require()

        builder.ConfigureServices(services =>
        {
            // Zamień Postgres na InMemory
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor != null)
                services.Remove(descriptor);

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseInMemoryDatabase($"Tests-{Guid.NewGuid()}"));

            // Test auth zamiast JWT z cookie
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                options.DefaultChallengeScheme = TestAuthHandler.SchemeName;
            })
            .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(
                TestAuthHandler.SchemeName, _ => { });
        });
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
        // Header: Authorization: Test <role>|<userId>
        // np. "Test user|user-123" albo "Test admin|admin-1"
        if (!Request.Headers.TryGetValue("Authorization", out var header))
        {
            return Task.FromResult(AuthenticateResult.Fail("Missing Authorization header"));
        }

        var value = header.ToString();
        if (!value.StartsWith("Test ", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid scheme"));
        }

        var payload = value["Test ".Length..].Trim();
        var parts = payload.Split('|');
        var role = parts.ElementAtOrDefault(0) ?? "user";
        var userId = parts.ElementAtOrDefault(1) ?? "test-user-id";

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Email, $"{userId}@test.com"),
            new Claim(ClaimTypes.Role, role)
        };

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}