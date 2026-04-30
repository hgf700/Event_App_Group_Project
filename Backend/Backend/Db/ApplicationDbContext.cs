using Microsoft.EntityFrameworkCore;
using Twilio.TwiML.Voice;
using static QuestPDF.Helpers.Colors;

namespace Backend.Db;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        

    
    
    
    }
}
