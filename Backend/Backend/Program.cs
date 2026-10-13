using EventApp.Domain.Model;
using EventApp.Infrastructure.Db;
using EventApp.Infrastructure.ExtraTools;
using EventApp.Services.Interfaces;
using EventApp.Services.Model;
using EventApp.Services.Services;
using EventApp.Services.Services.Interface;
using EventApp.Services.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Polly;
using Prometheus;
using QuestPDF.Infrastructure;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.Grafana.Loki;
using Stripe;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
QuestPDF.Settings.License = LicenseType.Community;

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

builder.Services.AddControllers();
// cykle przy relacjach chyba w db
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
var connectionString = builder.Configuration.GetConnectionString("Default");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString, o =>
        o.EnableRetryOnFailure()));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

//logs
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.File(
        "Logs/log.txt",
        rollingInterval: RollingInterval.Day,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}{NewLine}"
    )
    .WriteTo.GrafanaLoki("http://localhost:3100")
    .CreateLogger();

builder.Host.UseSerilog();

//app services
builder.Services.AddScoped<IQrCodeService, QrCodeService>();
builder.Services.AddScoped<ISmsService, SmsService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IOauthRefreshService, OauthRefreshService>();
builder.Services.AddSingleton<IRefreshTokenEncryptionService, RefreshTokenEncryptionService>();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<ISeedDbService, SeedDbService>();
builder.Services.AddScoped<ISendOrDownloadFromApiService, SendOrDownloadFromApiService>();
builder.Services.AddScoped<IPdfService, PdfService>();

//controller services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IPaymentService, PaymentService>();
builder.Services.AddScoped<IUserService, UserService>();

builder.Services.AddAuthorization();

//dev identity
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

//builder.Services.Configure<IdentityOptions>(options =>
//{
//    options.Password.RequiredLength = 5;
//    options.Password.RequireDigit = true;
//    options.Password.RequireLowercase = true;
//    options.Password.RequireUppercase = false;
//    options.Password.RequireNonAlphanumeric = false;

//    options.Lockout.DefaultLockoutTimeSpan =
//        TimeSpan.FromMinutes(15);

//    options.Lockout.MaxFailedAccessAttempts = 5;
//    options.Lockout.AllowedForNewUsers = true;

//    options.User.RequireUniqueEmail = true;
//});

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

string googleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID");
string googleClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET");
string JWT_SECRET = Environment.GetEnvironmentVariable("JWT_SECRET");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
//oauth
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWT_SECRET)),
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

//bez oauth
//.AddJwtBearer(options =>
//{
//    options.TokenValidationParameters = new TokenValidationParameters
//    {
//        ValidateIssuer = false,
//        ValidateAudience = false,
//        ValidateLifetime = true,
//        ValidateIssuerSigningKey = true,
//        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWT_SECRET)
//        ),
//        ClockSkew = TimeSpan.Zero
//    };
//});

//credentials jesli korzystam z cookie
builder.Services.AddCors(options =>
{
    options.AddPolicy("Prod", policy => policy
            .WithOrigins("http://localhost:4200")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Globalny limit IP — obejmuje wszystkie endpointy.
    options.GlobalLimiter =
        PartitionedRateLimiter.CreateChained(
            PartitionedRateLimiter.Create<HttpContext, string>(context =>
            {
                var ip = context.Connection.RemoteIpAddress?.ToString()
                         ?? "unknown-ip";

                return RateLimitPartition.GetFixedWindowLimiter(
                    $"ip:{ip}",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 300,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            })
        );

    // GET — limit per użytkownik.
    options.AddPolicy("GetPolicy", context =>
    {
        var key = GetUserKey(context);

        return RateLimitPartition.GetFixedWindowLimiter(
            $"get:{key}",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 120,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });

    // POST — limit per użytkownik.
    options.AddPolicy("PostPolicy", context =>
    {
        var key = GetUserKey(context);

        return RateLimitPartition.GetFixedWindowLimiter(
            $"post:{key}",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });
});

static string GetUserKey(HttpContext context)
{
    // Identyfikator z uwierzytelnionego JWT.
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var userId = context.User.FindFirstValue(
            ClaimTypes.NameIdentifier);

        if (!string.IsNullOrWhiteSpace(userId))
            return $"user:{userId}";
    }

    // Fallback dla niezalogowanych użytkowników.
    var ip = context.Connection.RemoteIpAddress?.ToString()
             ?? "unknown-ip";

    return $"ip:{ip}";
}

builder.Services.AddHttpClient();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    await IdentitySeeder.SeedAsync(scope.ServiceProvider);
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler();
    app.UseHsts();
}

Console.WriteLine(app.Environment.EnvironmentName);

app.UseHttpsRedirection();
app.UseRouting();

app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["X-Frame-Options"] = "DENY";

        // Dla API zwracającego dane wrażliwe.
        context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";

        context.Response.Headers["Pragma"] = "no-cache";
        context.Response.Headers["Expires"] = "0";

        return Task.CompletedTask;
    });

    await next();
});

app.UseCors("Prod");

app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();

app.UseSerilogRequestLogging();

//prometheus
app.UseHttpMetrics();
app.MapMetrics();

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