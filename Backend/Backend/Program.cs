using Backend.Db;
using Backend.Identity;
using Backend.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Stripe;

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

builder.Services.AddControllers();

builder.Services.AddOpenApi();

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

//builder.Services.AddTransient<IEmailSender, WebApplication1.ExtraTools.NullEmailSender>();
builder.Services.AddHttpClient();
builder.Services.AddScoped<QrCodeService>();
builder.Services.AddScoped<SmsService>();
builder.Services.AddScoped<EmailService>();
builder.Services.AddScoped<OauthRefreshService>();
builder.Services.AddSingleton<TokenEncryptionService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("Prod",
        policy => policy
            .WithOrigins("http://localhost:4200")
            .AllowAnyMethod()
            .AllowAnyHeader());
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
