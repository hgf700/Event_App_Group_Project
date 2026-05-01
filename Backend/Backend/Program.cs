using Backend.Db;
using Backend.ExtraTools;
using Backend.Identity;
using Backend.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
//using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Stripe;
//using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

//DotNetEnv.Env.Load();

builder.Services.AddControllers();

builder.Services.AddOpenApi();

//var env = builder.Environment;

var connectionString =
    builder.Configuration.GetConnectionString("Default");

if (string.IsNullOrWhiteSpace(connectionString))
    throw new Exception("Missing connection string 'Default'");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString, o =>
        o.EnableRetryOnFailure()));


builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

//builder.Services.AddTransient<IEmailSender, NullEmailSender>();
builder.Services.AddHttpClient();
builder.Services.AddScoped<QrCodeService>();
builder.Services.AddScoped<SmsService>();
builder.Services.AddScoped<EmailService>();
builder.Services.AddScoped<OauthRefreshService>();
builder.Services.AddSingleton<TokenEncryptionService>();

builder.Services.AddAuthorization();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequiredLength = 1;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 10;
    options.Lockout.AllowedForNewUsers = false;

    options.User.RequireUniqueEmail = false;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
});

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/var/dpkeys"))
    .SetApplicationName("projekt-app");

// Google OAuth z refresh tokenem
string googleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID");
string googleClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET");

builder.Services
    .AddAuthentication()
    .AddGoogle(options =>
    {
        options.ClientId = googleClientId;
        options.ClientSecret = googleClientSecret;
        options.CallbackPath = "/signin-google";
        options.AccessType = "offline";
        options.SaveTokens = true;
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy("Prod",
        policy => policy
            .WithOrigins("http://localhost:4200")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});

//builder.Services.AddRateLimiter(options =>
//{
//    options.AddFixedWindowLimiter("RateLimitGet", opt =>
//    {
//        opt.PermitLimit = 30;
//        opt.Window = TimeSpan.FromSeconds(2);
//        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
//        opt.QueueLimit = 10;
//    });

//    options.AddFixedWindowLimiter("RateLimitPost", opt =>
//    {
//        opt.PermitLimit = 3;
//        opt.Window = TimeSpan.FromSeconds(10);
//        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
//        opt.QueueLimit = 2;
//    });
//});

var app = builder.Build();

// Middleware bezpieczeństwa
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

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.UseCors("Prod");

app.MapControllers();

// MIGRATIONS (tylko DEV/PROD, NIE TESTY)
if (!app.Environment.IsEnvironment("UnitTest") &&
    !app.Environment.IsEnvironment("IntegrationTest"))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    try
    {
        db.Database.Migrate();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Migration failed: {ex.Message}");
        throw;
    }
}

app.Run();

// potrzebne dla WebApplicationFactory
public partial class Program { }