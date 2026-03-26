using Microsoft.Extensions.Options;
using MailKit.Net.Smtp;
using MimeKit;
using Microsoft.Extensions.Configuration;

namespace CyberBrief.Services.Email_sending
{
    public interface IEmailService
    {
        Task SendOtpAsync(string email, string otp);
        Task SendEmailConfirmationAsync(string toEmail, string userName, string confirmationLink);
        Task SendPasswordResetAsync(string toEmail, string userName, string resetLink);
    }

    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        // ── shared send helper ────────────────────────────────────────────────
        private async Task SendAsync(MimeMessage message)
        {
            var server = _config["EmailSettings:SmtpServer"];
            var port = int.Parse(_config["EmailSettings:Port"] ?? "587");
            var senderEmail = _config["EmailSettings:SenderEmail"];
            var password = _config["EmailSettings:Password"];

            using var client = new SmtpClient();
            await client.ConnectAsync(server, port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(senderEmail, password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }

        private MimeMessage CreateBaseMessage(string toEmail, string toName, string subject)
        {
            var senderName = _config["EmailSettings:SenderName"];
            var senderEmail = _config["EmailSettings:SenderEmail"];

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(senderName, senderEmail));
            message.To.Add(new MailboxAddress(toName, toEmail));
            message.Subject = subject;
            return message;
        }

        // ── OTP ───────────────────────────────────────────────────────────────
        public async Task SendOtpAsync(string email, string otp)
        {
            var message = CreateBaseMessage(email, "", "🛡️ CyberBrief: Your Verification Code");

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
<div style=""background-color:#f4f7f6;padding:50px 0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;"">
  <table align=""center"" border=""0"" cellpadding=""0"" cellspacing=""0"" width=""500""
         style=""background-color:#ffffff;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.1);
                overflow:hidden;border-top:4px solid #007bff;"">
    <tr>
      <td align=""center"" style=""padding:40px 20px 20px 20px;"">
        <div style=""background-color:#e7f3ff;width:60px;height:60px;line-height:60px;
                    border-radius:50%;margin-bottom:20px;"">
          <span style=""font-size:30px;"">🛡️</span>
        </div>
        <h2 style=""color:#333;margin:0;font-size:24px;"">Verify Your Identity</h2>
        <p style=""color:#666;line-height:1.5;margin-top:10px;"">
          We received a request to perform a <strong>Data Breach Scan</strong> for your account.
          Please use the secure code below to continue.
        </p>
      </td>
    </tr>
    <tr>
      <td align=""center"" style=""padding:10px 40px;"">
        <div style=""background-color:#f8f9fa;border:2px dashed #dee2e6;border-radius:12px;
                    padding:25px;margin:10px 0;"">
          <span style=""font-size:42px;font-weight:bold;color:#007bff;letter-spacing:8px;
                       font-family:'Courier New',Courier,monospace;"">
            {otp}
          </span>
        </div>
      </td>
    </tr>
    <tr>
      <td align=""center"" style=""padding:20px 40px 40px 40px;"">
        <p style=""color:#999;font-size:13px;margin-bottom:25px;"">
          This code is valid for <strong>10 minutes</strong>.<br/>
          If you didn't request this check, you can safely ignore this email.
        </p>
        {Footer()}
      </td>
    </tr>
  </table>
</div>"
            };

            message.Body = bodyBuilder.ToMessageBody();
            await SendAsync(message);
        }

        // ── Email confirmation ─────────────────────────────────────────────────
        public async Task SendEmailConfirmationAsync(string toEmail, string userName, string confirmationLink)
        {
            var message = CreateBaseMessage(toEmail, userName, "✅ CyberBrief: Confirm Your Email Address");

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
<div style=""background-color:#f4f7f6;padding:50px 0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;"">
  <table align=""center"" border=""0"" cellpadding=""0"" cellspacing=""0"" width=""500""
         style=""background-color:#ffffff;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.1);
                overflow:hidden;border-top:4px solid #28a745;"">
    <tr>
      <td align=""center"" style=""padding:40px 20px 20px 20px;"">
        <div style=""background-color:#eaffea;width:60px;height:60px;line-height:60px;
                    border-radius:50%;margin-bottom:20px;"">
          <span style=""font-size:30px;"">✅</span>
        </div>
        <h2 style=""color:#333;margin:0;font-size:24px;"">Confirm Your Email</h2>
        <p style=""color:#666;line-height:1.5;margin-top:10px;"">
          Welcome to <strong>CyberBrief</strong>, {userName}! 🎉<br/>
          You're one step away from securing your account.
          Click the button below to verify your email address.
        </p>
      </td>
    </tr>
    <tr>
      <td align=""center"" style=""padding:10px 40px;"">
        <div style=""background-color:#f8f9fa;border-radius:12px;padding:30px;margin:10px 0;"">
          <a href=""{confirmationLink}""
             style=""display:inline-block;background-color:#28a745;color:#ffffff;
                    text-decoration:none;padding:14px 36px;border-radius:8px;
                    font-size:16px;font-weight:600;letter-spacing:0.5px;"">
            Confirm My Email
          </a>
        </div>
        <p style=""color:#999;font-size:12px;margin-top:8px;"">
          Or copy and paste this link into your browser:<br/>
          <a href=""{confirmationLink}"" style=""color:#28a745;word-break:break-all;font-size:11px;"">
            {confirmationLink}
          </a>
        </p>
      </td>
    </tr>
    <tr>
      <td align=""center"" style=""padding:20px 40px 40px 40px;"">
        <p style=""color:#999;font-size:13px;margin-bottom:25px;"">
          This link expires in <strong>24 hours</strong>.<br/>
          If you didn't create a CyberBrief account, you can safely ignore this email.
        </p>
        {Footer()}
      </td>
    </tr>
  </table>
</div>"
            };

            message.Body = bodyBuilder.ToMessageBody();
            await SendAsync(message);
        }

        // ── Password reset ─────────────────────────────────────────────────────
        public async Task SendPasswordResetAsync(string toEmail, string userName, string resetLink)
        {
            var message = CreateBaseMessage(toEmail, userName, "🔐 CyberBrief: Password Reset Request");

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
<div style=""background-color:#f4f7f6;padding:50px 0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;"">
  <table align=""center"" border=""0"" cellpadding=""0"" cellspacing=""0"" width=""500""
         style=""background-color:#ffffff;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.1);
                overflow:hidden;border-top:4px solid #dc3545;"">
    <tr>
      <td align=""center"" style=""padding:40px 20px 20px 20px;"">
        <div style=""background-color:#fff0f0;width:60px;height:60px;line-height:60px;
                    border-radius:50%;margin-bottom:20px;"">
          <span style=""font-size:30px;"">🔐</span>
        </div>
        <h2 style=""color:#333;margin:0;font-size:24px;"">Password Reset Request</h2>
        <p style=""color:#666;line-height:1.5;margin-top:10px;"">
          Hi <strong>{userName}</strong>, we received a request to reset your password.<br/>
          Click the button below to choose a new one.
        </p>
      </td>
    </tr>
    <tr>
      <td align=""center"" style=""padding:10px 40px;"">
        <div style=""background-color:#f8f9fa;border-radius:12px;padding:30px;margin:10px 0;"">
          <a href=""{resetLink}""
             style=""display:inline-block;background-color:#dc3545;color:#ffffff;
                    text-decoration:none;padding:14px 36px;border-radius:8px;
                    font-size:16px;font-weight:600;letter-spacing:0.5px;"">
            Reset My Password
          </a>
        </div>
        <p style=""color:#999;font-size:12px;margin-top:8px;"">
          Or copy and paste this link into your browser:<br/>
          <a href=""{resetLink}"" style=""color:#dc3545;word-break:break-all;font-size:11px;"">
            {resetLink}
          </a>
        </p>
      </td>
    </tr>
    <tr>
      <td align=""center"" style=""padding:20px 40px 40px 40px;"">
        <div style=""background-color:#fff8e1;border-left:4px solid #ffc107;
                    border-radius:4px;padding:12px 16px;margin-bottom:20px;text-align:left;"">
          <p style=""color:#856404;font-size:13px;margin:0;"">
            ⚠️ This link expires in <strong>1 hour</strong>.
            If you didn't request a password reset, please secure your account immediately.
          </p>
        </div>
        <p style=""color:#999;font-size:13px;margin-bottom:25px;"">
          If you didn't make this request, you can safely ignore this email.<br/>
          Your password will remain unchanged.
        </p>
        {Footer()}
      </td>
    </tr>
  </table>
</div>"
            };

            message.Body = bodyBuilder.ToMessageBody();
            await SendAsync(message);
        }

        // ── Shared footer snippet ──────────────────────────────────────────────
        private static string Footer() => @"
<div style=""border-top:1px solid #eee;padding-top:20px;"">
  <span style=""color:#333;font-weight:600;font-size:14px;"">CyberBrief Security Platform</span><br/>
  <small style=""color:#bbb;"">Misr University for Science and Technology Project</small>
</div>";
    }
}