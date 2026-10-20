using EventApp.Services.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using EventApp.Domain.Model;

namespace EventApp.Infrastructure.Db;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<ApplicationUser> Users { get; set; }
    public DbSet<Event> Events { get; set; }
    public DbSet<UserEvent> UserEvents { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<Bookmark> Bookmarks { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<UserEvent>()
            .HasKey(ue => ue.Id);

        modelBuilder.Entity<UserEvent>()
            .HasOne(ue => ue.User)
            .WithMany(u => u.UserEvents)
            .HasForeignKey(ue => ue.UserId);

        modelBuilder.Entity<UserEvent>()
            .HasOne(ue => ue.Event)
            .WithMany(e => e.UserEvents)
            .HasForeignKey(ue => ue.EventId);

        modelBuilder.Entity<RefreshToken>()
            .HasOne(rt => rt.User)
            .WithMany(u => u.RefreshTokens)
            .HasForeignKey(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<Bookmark>()
            .HasOne(e => e.Event)
            .WithMany()
            .HasForeignKey(e => e.EventId);

        modelBuilder.Entity<Bookmark>()
            .HasOne(e => e.User)
            .WithMany()
            .HasForeignKey(e => e.UserId);
    }
}
