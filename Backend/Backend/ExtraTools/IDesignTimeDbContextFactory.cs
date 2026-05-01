namespace Backend.ExtraTools;


//public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
//{
//    public ApplicationDbContext CreateDbContext(string[] args)
//    {
//        var config = new ConfigurationBuilder()
//            .SetBasePath(Directory.GetCurrentDirectory())
//            .AddJsonFile("appsettings.json")
//            .Build();

//        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
//        optionsBuilder.UseSqlServer(
//            config.GetConnectionString("DefaultConnection")
//        );

//        return new ApplicationDbContext(optionsBuilder.Options);
//    }
//}
//public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
//{
//    public ApplicationDbContext CreateDbContext(string[] args)
//    {
//        var connectionString = Environment.GetEnvironmentVariable("CONNECTION_STRING");

//        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
//        optionsBuilder.UseSqlServer(connectionString);

//        return new ApplicationDbContext(optionsBuilder.Options);
//    }
//}



