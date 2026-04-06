using CyberBrief.DTOs.Auth;
using CyberBrief.Models.User;
using CyberBrief.Repository;
using CyberBrief.Services.Email_sending;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CyberBrief.Services.User
{
    public interface IAuthService
    {
        Task<(bool Success, string Message)> RegisterAsync(RegisterDto dto, string origin);
        Task<(bool Success, string Token, string Message)> LoginAsync(LoginDto dto);
        Task<(bool Success, string Message)> ConfirmEmailAsync(string userId, string token);
        Task<(bool Success, string Message)> ForgotPasswordAsync(ForgotPasswordDto dto, string origin);
        Task<(bool Success, string Message)> ResetPasswordAsync(ResetPasswordDto dto);
        Task<(bool Success, string Message)> ChangePasswordAsync(string userId, ChangePasswordDto dto);
        Task<(bool Success, string Message)> DeleteAccountAsync(string userId);
        Task<(bool Success, string Message)> ValidateResetTokenAsync(string email, string token);
    }

    // Services/AuthService.cs
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepo;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _config;

        public AuthService(IUserRepository userRepo, IEmailService emailService, IConfiguration config)
        {
            _userRepo = userRepo;
            _emailService = emailService;
            _config = config;
        }

        public async Task<(bool Success, string Message)> RegisterAsync(RegisterDto dto, string origin)
        {
            var existing = await _userRepo.GetByEmailAsync(dto.Email);
            if (existing is not null)
                return (false, "Email is already registered.");

            var user = new BaseUser
            {
                FirstName = dto.FirstName,
                LastName = dto.LastName,
                Email = dto.Email,
                UserName = dto.Email
            };

            var result = await _userRepo.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
                return (false, string.Join(", ", result.Errors.Select(e => e.Description)));

            // send confirmation email
            var token = await _userRepo.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var link = $"https://cybershield.tecisfun.cloud/confirm-email?userId={user.Id}&token={encodedToken}";

            await _emailService.SendEmailConfirmationAsync(user.Email!, user.FullName, link);

            return (true, "Registration successful. Please check your email to confirm your account.");
        }

        public async Task<(bool Success, string Token, string Message)> LoginAsync(LoginDto dto)
        {
            var user = await _userRepo.GetByEmailAsync(dto.Email);
            if (user is null)
                return (false, string.Empty, "Invalid email or password.");

            if (!await _userRepo.CheckPasswordAsync(user, dto.Password))
                return (false, string.Empty, "Invalid email or password.");

            if (!user.EmailConfirmed)
                return (false, string.Empty, "Please confirm your email before logging in.");

            var token = GenerateJwtToken(user);
            return (true, token, "Login successful.");
        }

        public async Task<(bool Success, string Message)> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user is null)
                return (false, "Invalid user.");

            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var result = await _userRepo.ConfirmEmailAsync(user, decodedToken);

            return result.Succeeded
                ? (true, "Email confirmed successfully.")
                : (false, string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        public async Task<(bool Success, string Message)> ForgotPasswordAsync(ForgotPasswordDto dto, string origin)
        {
            var user = await _userRepo.GetByEmailAsync(dto.Email);

            // always return success to avoid email enumeration
            if (user is null || !user.EmailConfirmed)
                return (true, "If that email exists, a reset link has been sent.");

            var token = await _userRepo.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var link = $"https://cybershield.tecisfun.cloud/reset-password?email={user.Email}&token={encodedToken}";

            await _emailService.SendPasswordResetAsync(user.Email!, user.FullName, link);

            return (true, "If that email exists, a reset link has been sent.");
        }

        public async Task<(bool Success, string Message)> ResetPasswordAsync(ResetPasswordDto dto)
        {
            var user = await _userRepo.GetByEmailAsync(dto.Email);
            if (user is null)
                return (false, "Invalid request.");

            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(dto.Token));
            var result = await _userRepo.ResetPasswordAsync(user, decodedToken, dto.NewPassword);

            return result.Succeeded
                ? (true, "Password reset successfully.")
                : (false, string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        public async Task<(bool Success, string Message)> ChangePasswordAsync(string userId, ChangePasswordDto dto)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user is null)
                return (false, "User not found.");

            var result = await _userRepo.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);

            return result.Succeeded
                ? (true, "Password changed successfully.")
                : (false, string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        public async Task<(bool Success, string Message)> DeleteAccountAsync(string userId)
        {
            var user = await _userRepo.GetByIdAsync(userId);
            if (user is null)
                return (false, "User not found.");

            var result = await _userRepo.DeleteAsync(user);

            return result.Succeeded
                ? (true, "Account deleted successfully.")
                : (false, string.Join(", ", result.Errors.Select(e => e.Description)));
        }
        public async Task<(bool Success, string Message)> ValidateResetTokenAsync(string email, string token)
        {
            var user = await _userRepo.GetByEmailAsync(email);
            if (user is null)
                return (false, "Invalid request.");

            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var isValid = await _userRepo.VerifyUserTokenAsync(user, "Default", "ResetPassword", decodedToken);

            return isValid
                ? (true, "Token is valid.")
                : (false, "This reset link has expired or is invalid.");
        }

        private string GenerateJwtToken(BaseUser user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email!),
            new Claim(ClaimTypes.Name, user.FullName),
        };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(7),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
