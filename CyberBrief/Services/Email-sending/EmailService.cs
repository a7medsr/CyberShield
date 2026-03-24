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
                HtmlBody = $@"
    <div style=""background-color: #f4f7f6; padding: 50px 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;"">
        <table align=""center"" border=""0"" cellpadding=""0"" cellspacing=""0"" width=""500"" style=""background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); overflow: hidden; border-top: 4px solid #007bff;"">
            <tr>
                <td align=""center"" style=""padding: 40px 20px 20px 20px;"">
                    <div style=""background-color: #e7f3ff; width: 60px; height: 60px; line-height: 60px; border-radius: 50%; margin-bottom: 20px;"">
                        <span style=""font-size: 30px;"">🛡️</span>
                    </div>
                    <h2 style=""color: #333; margin: 0; font-size: 24px;"">Verify Your Identity</h2>
                    <p style=""color: #666; line-height: 1.5; margin-top: 10px;"">
                        We received a request to perform a <strong>Data Breach Scan</strong> for your account. 
                        Please use the secure code below to continue.
                    </p>
                </td>
            </tr>
            <tr>
                <td align=""center"" style=""padding: 10px 40px;"">
                    <div style=""background-color: #f8f9fa; border: 2px dashed #dee2e6; border-radius: 12px; padding: 25px; margin: 10px 0;"">
                        <span style=""font-size: 42px; font-weight: bold; color: #007bff; letter-spacing: 8px; font-family: 'Courier New', Courier, monospace;"">
                            {otp}
                        </span>
                    </div>
                </td>
            </tr>
            <tr>
                <td align=""center"" style=""padding: 20px 40px 40px 40px;"">
                    <p style=""color: #999; font-size: 13px; margin-bottom: 25px;"">
                        This code is valid for <strong>10 minutes</strong>. <br/>
                        If you didn't request this check, you can safely ignore this email.
                    </p>
                    <div style=""border-top: 1px solid #eee; padding-top: 20px;"">
                        <span style=""color: #333; font-weight: 600; font-size: 14px;"">CyberBrief Security Platform</span><br/>
                        <small style=""color: #bbb;"">Misr University for Science and Technology Project</small>
                    </div>
                </td>
            </tr>
        </table>
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
