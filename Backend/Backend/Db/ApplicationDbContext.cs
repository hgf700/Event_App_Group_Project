using Backend.Identity;
using Backend.Models.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Twilio.TwiML.Voice;
using static QuestPDF.Helpers.Colors;

namespace Backend.Db;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<ApplicationUser> Users { get; set; }
    public DbSet<Event> Events { get; set; }
    public DbSet<UserEvent> UserEvents { get; set; }
    public DbSet<ExternalGoogleOAuthToken> ExternalGoogleOAuthTokens { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<UserEvent>()
            .HasKey(ue => new { ue.UserId, ue.EventId });

        modelBuilder.Entity<UserEvent>()
            .HasOne(ue => ue.User)
            .WithMany(u => u.UserEvents)
            .HasForeignKey(ue => ue.UserId);

        modelBuilder.Entity<UserEvent>()
            .HasOne(ue => ue.Event)
            .WithMany(e => e.UserEvents)
            .HasForeignKey(ue => ue.EventId);

        modelBuilder.Entity<ExternalGoogleOAuthToken>()
            .HasIndex(x => new { x.UserId, x.Provider })
            .IsUnique();

        //hardcoded
        modelBuilder.Entity<Event>().HasData(
            new Event
            {
                Id = 1,
                ExternalEventId = "ext-1001",
                TypeOfEvent = "concert",
                NameOfEvent = "Rock Night Krakow",
                UrlOfEvent = "https://example.com/events/rock-night",
                PhotoUrl = "https://example.com/images/rock.jpg",
                StartOfEvent = new DateTime(2026, 06, 15, 19, 0, 0, DateTimeKind.Utc),
                Address = "Main Street 12",
                City = "Krakow",
                Country = "Poland",
                NameOfClub = "Proxima Club"
            },
            new Event
            {
                Id = 2,
                ExternalEventId = "ext-1002",
                TypeOfEvent = "festival",
                NameOfEvent = "Summer Tech Fest",
                UrlOfEvent = "https://example.com/events/techfest",
                PhotoUrl = "https://example.com/images/tech.jpg",
                StartOfEvent = new DateTime(2026, 07, 20, 18, 0, 0, DateTimeKind.Utc),
                Address = "Expo Center 5",
                City = "Warsaw",
                Country = "Poland",
                NameOfClub = "Expo Arena"
            }
        );

        modelBuilder.Entity<ApplicationUser>().HasData(
            new ApplicationUser
            {
                Id = "user-1",
                UserName = "a",
                NormalizedUserName = "A",
                Email = "a",
                NormalizedEmail = "A",
                EmailConfirmed = true,
                PasswordHash = "A",
                IsOAuth = false,
                GoogleId = null,
                SecurityStamp = "STATIC-SECURITY-STAMP-1",
                ConcurrencyStamp = "STATIC-CONCURRENCY-STAMP-1"
            }
        );

        modelBuilder.Entity<UserEvent>().HasData(
            new UserEvent
            {
                UserId = "user-1",
                EventId = 1
            },
            new UserEvent
            {
                UserId = "user-1",
                EventId = 2
            }
        );

    }
}
