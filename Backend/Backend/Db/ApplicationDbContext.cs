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
    public DbSet<NotificationLog> NotificationLogs { get; set; }
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

        modelBuilder.Entity<NotificationLog>()
            .HasOne(u => u.User)
            .WithMany()
            .HasForeignKey(u => u.UserId);

        modelBuilder.Entity<NotificationLog>()
            .HasOne(e => e.Event)
            .WithMany()
            .HasForeignKey(e => e.EventId);
    }
}
