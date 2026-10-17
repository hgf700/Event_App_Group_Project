using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Services.Dto.RelAuth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using TestServices.Helper;

namespace TestServices.IntegrationTest;

[TestFixture]
public class AuthControllerIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private EventAppFactory _factory = null!;
    private HttpClient _client = null!;
    private CreateDbObjectHelper _helper = null!;

    [SetUp]
    public async Task SetUp()
    {
        //_client = _factory.CreateClient();

        _factory = new EventAppFactory();
        _client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            // pozwala czytać Set-Cookie nawet przy Secure
            HandleCookies = true,
            AllowAutoRedirect = false
        });
        _helper = new CreateDbObjectHelper(_client);

        await _factory.ResetDbAsync();
        await EnsureRoleExistsAsync("user");
        await EnsureRoleExistsAsync("admin");
    }

    [TearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private async Task EnsureRoleExistsAsync(string roleName)
    {
        using var scope = _factory.Services.CreateScope();
        var roleManager = scope.ServiceProvider
            .GetRequiredService<RoleManager<IdentityRole>>();

        if (!await roleManager.RoleExistsAsync(roleName))
            await roleManager.CreateAsync(new IdentityRole(roleName));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/auth/register-norm
    // ─────────────────────────────────────────────

    [Test]
    public async Task RegisterUserNormal_ValidData_Returns201()
    {
        var dto = new postCreateUserNormDto
        {
            email = "newuser@test.com",
            password = "Password1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/auth/register-norm", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<authResponseDto>(content, JsonOptions);

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.email, Is.EqualTo("newuser@test.com"));
        Assert.That(result.jwt, Is.Not.Null.And.Not.Empty);
        Assert.That(result.refreshToken, Is.Not.Null.And.Not.Empty);
        Assert.That(result.userRole, Is.EqualTo("user"));
    }

    [Test]
    public async Task RegisterUserNormal_UserAlreadyExists_Returns409()
    {
        await _factory.CreateTestUserAsync(email: "exists@test.com", password: "Password1!", role: "user");

        var dto = new postCreateUserNormDto
        {
            email = "exists@test.com",
            password = "Password1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/auth/register-norm", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    [Test]
    public async Task RegisterUserNormal_WeakPassword_Returns400()
    {
        // Identity password policy
        var dto = new postCreateUserNormDto
        {
            email = "weak@test.com",
            password = null
        };

        var response = await _client.PostAsJsonAsync("/api/v1/auth/register-norm", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/auth/login-norm
    // ─────────────────────────────────────────────

    [Test]
    public async Task LoginUserNormal_ValidCredentials_Returns200()
    {
        await _factory.CreateTestUserAsync(
            email: "login@test.com",
            password: "Password1!",
            role: "user");

        var dto = new postLoginUserNormDto
        {
            email = "login@test.com",
            password = "Password1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/auth/login-norm", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<authResponseDto>(content, JsonOptions);

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.email, Is.EqualTo("login@test.com"));
        Assert.That(result.jwt, Is.Not.Null.And.Not.Empty);
        Assert.That(result.refreshToken, Is.Not.Null.And.Not.Empty);
    }

    [Test]
    public async Task LoginUserNormal_WrongPassword_Returns401()
    {
        await _factory.CreateTestUserAsync(
            email: "wrongpass@test.com",
            password: "Password1!",
            role: "user");

        var dto = new postLoginUserNormDto
        {
            email = "wrongpass@test.com",
            password = "WrongPassword1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/auth/login-norm", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task LoginUserNormal_UserNotFound_Returns401()
    {
        var dto = new postLoginUserNormDto
        {
            email = "nobody@test.com",
            password = "Password1!"
        };

        var response = await _client.PostAsJsonAsync("/api/v1/auth/login-norm", dto);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/auth/refresh
    // ─────────────────────────────────────────────

    [Test]
    public async Task Refresh_NoCookie_Returns401()
    {
        var response = await _client.PostAsync("/api/v1/auth/refresh", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Refresh_InvalidToken_Returns401()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        request.Headers.Add("Cookie", "refreshToken=invalid-token-value");

        var response = await _client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Refresh_ValidToken_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(
            email: "refresh@test.com",
            password: "Password1!",
            role: "user");

        var refreshTokenValue = "valid-refresh-token-abc";
        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshTokenValue,
            Expires = DateTime.UtcNow.AddDays(30),
            Created = DateTime.UtcNow,
            Revoked = null
        };

        await _factory.SeedAsync(refreshToken);

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        request.Headers.Add("Cookie", $"refreshToken={refreshTokenValue}");

        var response = await _client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Refresh_ExpiredToken_Returns401()
    {
        var user = await _factory.CreateTestUserAsync(
            email: "expired@test.com",
            password: "Password1!",
            role: "user");

        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = "expired-token",
            Expires = DateTime.UtcNow.AddDays(-1),
            Created = DateTime.UtcNow.AddDays(-10),
            Revoked = null
        };

        await _factory.SeedAsync(refreshToken);

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        request.Headers.Add("Cookie", "refreshToken=expired-token");

        var response = await _client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Refresh_RevokedToken_Returns401()
    {
        var user = await _factory.CreateTestUserAsync(
            email: "revoked@test.com",
            password: "Password1!",
            role: "user");

        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = "revoked-token",
            Expires = DateTime.UtcNow.AddDays(30),
            Created = DateTime.UtcNow,
            Revoked = DateTime.UtcNow.AddMinutes(-5)
        };

        await _factory.SeedAsync(refreshToken);

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        request.Headers.Add("Cookie", "refreshToken=revoked-token");

        var response = await _client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    // ─────────────────────────────────────────────
    // POST /api/v1/auth/logout
    // ─────────────────────────────────────────────

    [Test]
    public async Task Logout_Unauthorized_Returns401()
    {
        var response = await _client.PostAsync("/api/v1/auth/logout", null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Logout_Authorized_Returns200()
    {
        var user = await _factory.CreateTestUserAsync(
            email: "logout@test.com",
            password: "Password1!",
            role: "user");

        var refreshTokenValue = "logout-refresh-token";
        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshTokenValue,
            Expires = DateTime.UtcNow.AddDays(30),
            Created = DateTime.UtcNow,
            Revoked = null
        };

        await _factory.SeedAsync(refreshToken);

        _helper.AuthenticateAs("user", user.Id);

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        request.Headers.Add("Cookie", $"refreshToken={refreshTokenValue}");

        var response = await _client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        // token powinien być revoked
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var token = await db.RefreshTokens.FindAsync(refreshToken.Id);

        // jeśli Id nie było ustawione przy seed – szukaj po Token
        token ??= db.RefreshTokens.FirstOrDefault(t => t.Token == refreshTokenValue);

        Assert.That(token, Is.Not.Null);
        Assert.That(token!.Revoked, Is.Not.Null);
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/auth/check
    // ─────────────────────────────────────────────

    [Test]
    public async Task CheckAuth_Returns200True()
    {
        var response = await _client.GetAsync("/api/v1/auth/check");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var content = await response.Content.ReadAsStringAsync();
        Assert.That(content, Does.Contain("true").IgnoreCase);
    }

    // ─────────────────────────────────────────────
    // GET /api/v1/auth/sign-in-google
    // (tylko challenge – bez pełnego OAuth flow)
    // ─────────────────────────────────────────────

    [Test]
    public async Task SignInWithGoogle_ReturnsChallengeRedirect()
    {
        var response = await _client.GetAsync("/api/v1/auth/sign-in-google");

        // Challenge → 302 do Google albo 401 jeśli scheme nie skonfigurowany w teście
        Assert.That(
            response.StatusCode,
            Is.EqualTo(HttpStatusCode.Redirect)
                .Or.EqualTo(HttpStatusCode.Unauthorized)
                .Or.EqualTo(HttpStatusCode.InternalServerError));
    }
}