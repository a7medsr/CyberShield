using Microsoft.EntityFrameworkCore;
using  CyberBrief.Models;
using CyberBrief.Models.Email_Checking;
using CyberBrief.Models.PassordCheaking;

namespace CyberBrief.Context
{
    public class CyberBriefDbContext : DbContext
    {
        public CyberBriefDbContext(DbContextOptions<CyberBriefDbContext> options) : base(options)
        {
        }
        //Container Scanning
        public DbSet<Image> Images { get; set; }
        public DbSet<Summary> Summarys { get; set; }
        public DbSet<Vulnerability> Vulnerabilities { get; set; }
        ///Email Cheacking
        public DbSet<Result> Results { get; set; }
        public DbSet<Found> Founds {  get; set; }
        public DbSet<EmailVerification> EmailVerifications { get; set; }
        //pass check
        public DbSet<PasswordAudit> PasswordAudits { get; set; }
        //triage
        public DbSet<TriageCache> TriageCaches { get; set; }

        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Summary>()
                .HasMany(s => s.Vulnerabilities)
                .WithMany(v => v.Summaries)
                .UsingEntity(j => j.ToTable("SummaryVulnerabilities")); 
        }
    }
}
