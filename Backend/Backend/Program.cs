using Backend.Db;
using Backend.ExtraTools;
using Backend.Identity;
using Backend.Models.Model;
using Backend.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Stripe;
using System.Text;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

builder.Services.AddControllers();
    //.AddJsonOptions(options =>
    //{
    //    options.JsonSerializerOptions.ReferenceHandler =
    //        System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
    //});

//swager
builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


//db
var connectionString =
    builder.Configuration.GetConnectionString("Default");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString, o =>
        o.EnableRetryOnFailure()));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

//logs
//Log.Logger = new LoggerConfiguration()
//    .MinimumLevel.Information()
//    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
//    .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
//    .Enrich.FromLogContext()
//    .WriteTo.File(
//        "Logs/log.txt",
//        rollingInterval: RollingInterval.Day,
//        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}"
//    )
//    .WriteTo.GrafanaLoki("http://localhost:3100")
//    .CreateLogger();

//builder.Host.UseSerilog();

//builder.Services.AddTransient<IEmailSender, NullEmailSender>();
builder.Services.AddHttpClient();
builder.Services.AddScoped<QrCodeService>();
builder.Services.AddScoped<SmsService>();
builder.Services.AddScoped<EmailService>();
builder.Services.AddScoped<OauthRefreshService>();
builder.Services.AddSingleton<RefreshTokenEncryptionService>();
builder.Services.AddScoped<JwtService>();
builder.Services.AddScoped<DownloadFromApi>();

builder.Services.AddAuthorization();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequiredLength = 1;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(1);
    options.Lockout.MaxFailedAccessAttempts = 20;
    options.Lockout.AllowedForNewUsers = false;

    options.User.RequireUniqueEmail = false;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    //options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
});

//chyba wazne cos z cookies
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/var/dpkeys"))
    .SetApplicationName("projekt-app");

// Google OAuth + jwt z refresh tokenem
string googleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID");
string googleClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET");
string JWT_SECRET = Environment.GetEnvironmentVariable("JWT_SECRET");

int zoauth = 0;

if (zoauth == 1)
{
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        //options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(JWT_SECRET)
            ),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };
    })
    .AddGoogle(options =>
    {
        options.ClientId = googleClientId;
        options.ClientSecret = googleClientSecret;
        options.CallbackPath = "/signin-google";
        options.SaveTokens = true;
    });
}
else
{
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(JWT_SECRET)
            ),
            ClockSkew = TimeSpan.Zero
        };
    });
}

builder.Services.AddCors(options =>
{
    options.AddPolicy("Prod",
        policy => policy
            .WithOrigins("http://localhost:4200")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});

builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("RateLimitGet", opt =>
    {
        opt.PermitLimit = 30;
        opt.Window = TimeSpan.FromSeconds(2);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 10;
    });

    options.AddFixedWindowLimiter("RateLimitPost", opt =>
    {
        opt.PermitLimit = 3;
        opt.Window = TimeSpan.FromSeconds(10);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 2;
    });
});

var app = builder.Build();

// Middleware bezpieczeństwa
//app.Use(async (context, next) =>
//{
//    context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
//    context.Response.Headers["Pragma"] = "no-cache";
//    context.Response.Headers["Expires"] = "-1";
//    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
//    context.Response.Headers["X-Frame-Options"] = "DENY";
//    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";

//    await next.Invoke();
//});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.UseCors("Prod");

app.MapControllers();

// MIGRATIONS (tylko DEV/PROD, NIE TESTY)
//if (!app.Environment.IsEnvironment("UnitTest") &&
//    !app.Environment.IsEnvironment("IntegrationTest"))
//{
//    using var scope = app.Services.CreateScope();
//    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

//    try
//    {
//        db.Database.Migrate();
//    }
//    catch (Exception ex)
//    {
//        Console.WriteLine($"Migration failed: {ex.Message}");
//        throw;
//    }
//}

app.Run();

// potrzebne dla WebApplicationFactory
public partial class Program { }