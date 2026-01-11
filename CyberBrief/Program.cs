using CyberBrief.Context;
using CyberBrief.Services;
using CyberBrief.Services;
using CyberBrief.Services.IServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Options;
using Scalar.AspNetCore;
using System.Net.Http.Headers;
using System.Net.Http.Headers;
using System.Text;

namespace CyberBrief
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            #region Url short expander
            // Add services to the container.
            // Configure HttpClient for URL expansion (no auto-redirect)
            builder.Services.AddHttpClient<IUrlExpanderService, UrlExpanderService>(client =>
            {
                client.Timeout = TimeSpan.FromSeconds(30);
                client.DefaultRequestHeaders.Add("User-Agent", "CyberShield-URLAnalyzer/1.0");
            })
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler()
            {
                AllowAutoRedirect = false // IMPORTANT: We handle redirects manually
            });

            // Configure HttpClient for safety analysis
            builder.Services.AddHttpClient<ISafetyAnalyzerService, AdvancedSafetyAnalyzerService>(client =>
            {
                client.Timeout = TimeSpan.FromSeconds(15);
                client.DefaultRequestHeaders.Add("User-Agent", "CyberShield-SecurityAnalyzer/1.0");
            });

            // Register services
            builder.Services.AddScoped<IUrlExpanderService, UrlExpanderService>();
            builder.Services.AddScoped<ISafetyAnalyzerService, AdvancedSafetyAnalyzerService>();
            #endregion

            #region Email chick
            builder.Services.AddSingleton<BreachDirectoryService>(sp =>
            {
                var httpClientFactory = sp.GetRequiredService<IHttpClientFactory>();
                var httpClient = httpClientFactory.CreateClient();
                httpClient.BaseAddress = new Uri("https://breachdirectory.p.rapidapi.com/");
                httpClient.DefaultRequestHeaders.Add("x-rapidapi-host", "breachdirectory.p.rapidapi.com");
                httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("bransh/1.0");

                return new BreachDirectoryService(
                    httpClient,
                    "cd849227fcmsha0865829942a226p196270jsnd1890868e127"
                );
            });

            // inside Main or builder setup
            builder.Services.AddHttpClient<PasswordInspectorService>();
            builder.Services.AddScoped<PasswordInspectorService>();
            builder.Services.AddScoped<ContainerServices>();


            #endregion

            #region Sandbox
            builder.Services.AddHttpClient<TriageService>();
            builder.Services.AddScoped<TriageService>(sp =>
            {
                var httpClient = sp.GetRequiredService<HttpClient>();
                var config = sp.GetRequiredService<IConfiguration>();
                return new TriageService(httpClient, config);
            });
            #endregion


            builder.Services.AddDbContext<CyberBriefDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("local")));


            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            // if (app.Environment.IsDevelopment())
            // {
            //     app.UseSwagger();
            //     app.UseSwaggerUI();
            // }
            app.UseSwagger(opt => opt.RouteTemplate = "openapi/{documentName}.json");
            app.MapScalarApiReference(opt =>
            {
                opt.Title = "AutoGrad API Documentation";
                opt.Theme = ScalarTheme.Default;
                opt.DefaultHttpClient = new(ScalarTarget.Http, ScalarClient.Http11);
            });

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
