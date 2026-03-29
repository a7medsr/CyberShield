using CyberBrief.Context;
using CyberBrief.Models.User;
using CyberBrief.Repository;
using CyberBrief.Services;
using CyberBrief.Services.Dashboard_Services;
using CyberBrief.Services.Email_sending;
using CyberBrief.Services.IServices;
using CyberBrief.Services.TriageSerivces;
using CyberBrief.Services.User;
using CyberBrief.Services.Web_scan_services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Text;

namespace CyberBrief
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            #region CORS
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", policy =>
                {
                    policy
                        .AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                });
            });
            #endregion

            #region Database
            builder.Services.AddDbContext<CyberBriefDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("local")));
            #endregion

            #region Identity
            builder.Services.AddIdentityCore<BaseUser>(options =>
            {
                options.Password.RequiredLength = 8;
                options.User.RequireUniqueEmail = true;
                options.SignIn.RequireConfirmedEmail = true;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<CyberBriefDbContext>()
            .AddDefaultTokenProviders();
            #endregion

            #region JWT
            var jwtKey = builder.Configuration["Jwt:Key"]!;

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    ValidAudience = builder.Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
                };
            });
            #endregion

            #region User services
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddScoped<IUserRepository, UserRepository>();
            builder.Services.AddScoped<IAuthService, AuthService>();
            builder.Services.AddTransient<IEmailService, EmailService>();
            #endregion

            #region URL expander
            builder.Services.AddHttpClient<IUrlExpanderService, UrlExpanderService>(client =>
            {
                client.Timeout = TimeSpan.FromSeconds(30);
                client.DefaultRequestHeaders.Add("User-Agent", "CyberShield-URLAnalyzer/1.0");
            })
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                AllowAutoRedirect = false
            });

            builder.Services.AddHttpClient<ISafetyAnalyzerService, AdvancedSafetyAnalyzerService>(client =>
            {
                client.Timeout = TimeSpan.FromSeconds(15);
                client.DefaultRequestHeaders.Add("User-Agent", "CyberShield-SecurityAnalyzer/1.0");
            });

            builder.Services.AddHttpClient<CVEexplanationService>(client =>
            {
                client.Timeout = TimeSpan.FromMinutes(5);
            });
            builder.Services.AddScoped<IDashboardService,DashboardService>();
            builder.Services.AddScoped<IUrlExpanderService, UrlExpanderService>();
            builder.Services.AddScoped<ISafetyAnalyzerService, AdvancedSafetyAnalyzerService>();
            builder.Services.AddScoped<ICVEexplanationService, CVEexplanationService>();
            builder.Services.AddScoped<IContainerServices, ContainerServices>();
            #endregion

            #region Email breach
            builder.Services.AddHttpClient<BreachDirectoryService>(client =>
            {
                client.BaseAddress = new Uri("https://breachdirectory.p.rapidapi.com/");
                client.DefaultRequestHeaders.Add("x-rapidapi-host", "breachdirectory.p.rapidapi.com");
                client.DefaultRequestHeaders.UserAgent.ParseAdd("bransh/1.0");
            });

            builder.Services.AddScoped<BreachDirectoryService>(sp =>
            {
                var httpClient = sp.GetRequiredService<IHttpClientFactory>()
                                   .CreateClient(nameof(BreachDirectoryService));
                var context = sp.GetRequiredService<CyberBriefDbContext>();
                var apiKey = "cd849227fcmsha0865829942a226p196270jsnd1890868e127";
                return new BreachDirectoryService(httpClient, apiKey, context);
            });

            builder.Services.AddHttpClient<IScanService, ScanService>(client =>
            {
                client.Timeout = TimeSpan.FromMinutes(10);
            });

            builder.Services.AddHttpClient<PasswordInspectorService>();
            builder.Services.AddScoped<PasswordInspectorService>();
            builder.Services.AddScoped<ContainerServices>();
            builder.Services.AddScoped<CVEexplanationService>();
            #endregion

            #region Sandbox
            builder.Services.AddHttpClient<TriageService>();
            #endregion

            #region Infrastructure
            builder.Services.AddHttpClient("ContainerScanner", client =>
            {
                client.BaseAddress = new Uri("https://containerscanner.tecisfun.cloud/");
                client.Timeout = TimeSpan.FromMinutes(2);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("CyberBrief-App/1.0");
            });

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
            #endregion

            var app = builder.Build();

            app.UseSwagger(opt => opt.RouteTemplate = "openapi/{documentName}.json");
            app.MapScalarApiReference(opt =>
            {
                opt.Title = "CyberBrief API Documentation";
                opt.Theme = ScalarTheme.Default;
                opt.DefaultHttpClient = new(ScalarTarget.Http, ScalarClient.Http11);
            });

            app.UseHttpsRedirection();

            app.UseCors("AllowAll");      

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();
            app.Run();
        }
    }
}