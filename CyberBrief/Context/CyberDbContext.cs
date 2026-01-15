using Microsoft.EntityFrameworkCore;
using  CyberBrief.Models;

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
        //public DbSet<SummaryVulnerability> SummaryVulnerabilities { get; set; }
        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Summary>()
                .HasMany(s => s.Vulnerabilities)
                .WithMany(v => v.Summaries)
                .UsingEntity(j => j.ToTable("SummaryVulnerabilities")); 
        }
    }
}
