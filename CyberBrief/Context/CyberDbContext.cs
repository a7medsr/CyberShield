using Microsoft.EntityFrameworkCore;

namespace CyberBrief.Context
{
    public class CyberBriefDbContext : DbContext
    {
        public CyberBriefDbContext(DbContextOptions<CyberBriefDbContext> options) : base(options)
        {
        }

        public DbSet<Image> Images { get; set; }
        public DbSet<Summary> Summarys { get; set; }
        public DbSet<Vulnerability> Vulnerabilities { get; set; }
    }
}
