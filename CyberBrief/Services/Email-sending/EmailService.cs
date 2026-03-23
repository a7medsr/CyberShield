using Microsoft.Extensions.Options;
using MailKit.Net.Smtp;
using MimeKit;
using Microsoft.Extensions.Configuration; 
namespace CyberBrief.Services.Email_sending
{
    public interface IEmailService
    {
        Task SendOtpAsync(string email, string otp);
    }

    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendOtpAsync(string email, string otp)
        {
            var message = new MimeMessage();

            // Reading directly from appsettings.json
            var senderName = _config["EmailSettings:SenderName"];
            var senderEmail = _config["EmailSettings:SenderEmail"];

            message.From.Add(new MailboxAddress(senderName, senderEmail));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = "🛡️ CyberBrief: Your Verification Code";

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"<div style='font-family: sans-serif;'>
                            <h2>Verification Code</h2>
                            <h1 style='color: #007bff;'>{otp}</h1>
                          </div>"
            };
            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();

            // Reading server details directly
            var server = _config["EmailSettings:SmtpServer"];
            var port = int.Parse(_config["EmailSettings:Port"] ?? "587");
            var password = _config["EmailSettings:Password"];

            await client.ConnectAsync(server, port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(senderEmail, password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
    }
}
