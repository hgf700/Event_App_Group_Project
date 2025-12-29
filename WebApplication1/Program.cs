using DotNetEnv;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using NuGet.Protocol;
using QuestPDF.Infrastructure;
using Stripe;
using System.Security.Claims;
using System.Text.Json;
using WebApplication1.Areas.Identity.Data;
using WebApplication1.Models;
using WebApplication1.Models.Identity;
using WebApplication1.ProjectSERVICES;

var builder = WebApplication.CreateBuilder(args);

QuestPDF.Settings.License = LicenseType.Community;
DotNetEnv.Env.Load();

builder.Services.AddControllersWithViews();

//var connectionString = Environment.GetEnvironmentVariable("CONNECTION_STRING");
//builder.Services.AddDbContext<ApplicationDbContext>(options =>
//    options.UseSqlServer(connectionString));

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")
    ));


builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddTransient<IEmailSender, WebApplication1.ExtraTools.NullEmailSender>();
builder.Services.AddHttpClient();
builder.Services.AddScoped<QrService>();
builder.Services.AddScoped<SmsService>();
builder.Services.AddScoped<EmailService>();

builder.Services.AddAuthorization();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequiredLength = 1;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 10;
    options.Lockout.AllowedForNewUsers = true;

    options.User.RequireUniqueEmail = false;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromHours(1); // D³u¿szy czas ¿ycia sesji
    options.SlidingExpiration = true;
    options.LoginPath = "/Identity/Account/Login";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.LogoutPath = "/Identity/Account/Logout";

    // <<< KLUCZOWA CZÊŒÆ: AUTOMATYCZNE ODŒWIE¯ANIE TOKENA <<<
    //options.Events.OnValidatePrincipal = async context =>
    //{
    //    var expiresAtValue = context.Properties.GetTokenValue("expires_at");
    //    if (DateTime.TryParse(expiresAtValue, out var expiresAt) && expiresAt < DateTime.UtcNow.AddMinutes(5))
    //    {
    //        var refreshToken = context.Properties.GetTokenValue("refresh_token");
    //        if (!string.IsNullOrEmpty(refreshToken))
    //        {
    //            var clientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID");
    //            var clientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET");

    //            var tokenRequestParameters = new Dictionary<string, string>
    //            {
    //                { "client_id", clientId },
    //                { "client_secret", clientSecret },
    //                { "refresh_token", refreshToken },
    //                { "grant_type", "refresh_token" }
    //            };

    //            using var client = new HttpClient();
    //            var requestContent = new FormUrlEncodedContent(tokenRequestParameters);
    //            var response = await client.PostAsync("https://oauth2.googleapis.com/token", requestContent);

    //            if (response.IsSuccessStatusCode)
    //            {
    //                var responseContent = await response.Content.ReadAsStringAsync();
    //                var tokenResponse = JsonDocument.Parse(responseContent).RootElement;

    //                var newAccessToken = tokenResponse.GetProperty("access_token").GetString();
    //                var newExpiresIn = tokenResponse.GetProperty("expires_in").GetInt32();
    //                var newExpiresAt = DateTime.UtcNow.AddSeconds(newExpiresIn);

    //                // Aktualizuj tokeny w kontekœcie
    //                context.Properties.UpdateTokenValue("access_token", newAccessToken);
    //                context.Properties.UpdateTokenValue("expires_at", newExpiresAt.ToString("o"));

    //                // Jeœli Google zwróci nowy refresh token (rzadko, ale mo¿e), zapisz go
    //                if (tokenResponse.TryGetProperty("refresh_token", out var newRefreshTokenElem))
    //                {
    //                    var newRefreshToken = newRefreshTokenElem.GetString();
    //                    context.Properties.UpdateTokenValue("refresh_token", newRefreshToken);
    //                }

    //                // Ponowne podpisanie u¿ytkownika z nowymi tokenami
    //                context.ShouldRenew = true;
    //            }
    //            else
    //            {
    //                // Jeœli refresh nie uda³ siê – wyloguj u¿ytkownika
    //                context.RejectPrincipal();
    //                await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    //            }
    //        }
    //    }
    //};

});

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/var/dpkeys"))
    .SetApplicationName("projekt-app");

// Google OAuth z refresh tokenem
string googleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID");
string googleClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET");

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
})
.AddCookie()
.AddGoogle(options =>
{
    options.ClientId = googleClientId;
    options.ClientSecret = googleClientSecret;
    options.CallbackPath = "/signin-google";

    // <<< WA¯NE: ¯eby otrzymaæ refresh token przy pierwszym logowaniu >>>
    options.AccessType = "offline";        // Wymaga refresh tokena

    options.SaveTokens = true;             // Zapisz tokeny w cookie

    options.Events.OnTicketReceived = async context =>
    {
        var refreshToken = context.Properties.GetTokenValue("refresh_token");

        if (!string.IsNullOrEmpty(refreshToken))
        {
            var userId = context.Principal.FindFirstValue(ClaimTypes.NameIdentifier);

            //await tokenStore.SaveGoogleRefreshTokenAsync(userId, refreshToken);
        }
    };
    //options.Scope.Add("profile");
    //options.Scope.Add("email");

    //// Opcjonalnie: zdarzenie po odebraniu ticketu
    //options.Events.OnCreatingTicket = context =>
    //{
    //    // Zapewnia, ¿e refresh token jest zapisany
    //    var expiresIn = context.Properties.GetTokenValue("expires_in");
    //    //if (int.TryParse(expiresIn, out int seconds))
    //    //{
    //    //    context.Properties.UpdateTokenValue("expires_in", "30"); // 30 sekund zamiast godziny
    //    //    var newExpiresAt = DateTime.UtcNow.AddSeconds(30);
    //    //    context.Properties.UpdateTokenValue("expires_at", newExpiresAt.ToString("o"));
    //    //}


    //    return Task.CompletedTask;
    //};
});

builder.Services.AddRazorPages();

var app = builder.Build();

// Middleware bezpieczeñstwa
app.Use(async (context, next) =>
{
    context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    context.Response.Headers["Pragma"] = "no-cache";
    context.Response.Headers["Expires"] = "-1";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";

    await next.Invoke();
});

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();