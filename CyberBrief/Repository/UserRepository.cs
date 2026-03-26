using CyberBrief.Models.User;
using Microsoft.AspNetCore.Identity;

namespace CyberBrief.Repository
{
    // Repositories/IUserRepository.cs
    public interface IUserRepository
    {
        Task<BaseUser?> GetByIdAsync(string id);
        Task<BaseUser?> GetByEmailAsync(string email);
        Task<IdentityResult> CreateAsync(BaseUser user, string password);
        Task<IdentityResult> UpdateAsync(BaseUser user);
        Task<IdentityResult> DeleteAsync(BaseUser user);
        Task<bool> CheckPasswordAsync(BaseUser user, string password);
        Task<string> GenerateEmailConfirmationTokenAsync(BaseUser user);
        Task<IdentityResult> ConfirmEmailAsync(BaseUser user, string token);
        Task<string> GeneratePasswordResetTokenAsync(BaseUser user);
        Task<IdentityResult> ResetPasswordAsync(BaseUser user, string token, string newPassword);
        Task<IdentityResult> ChangePasswordAsync(BaseUser user, string current, string newPassword);
        Task<IList<string>> GetRolesAsync(BaseUser user);
    }

    // Repositories/UserRepository.cs
    public class UserRepository : IUserRepository
    {
        private readonly UserManager<BaseUser> _userManager;

        public UserRepository(UserManager<BaseUser> userManager)
        {
            _userManager = userManager;
        }

        public Task<BaseUser?> GetByIdAsync(string id) =>
            _userManager.FindByIdAsync(id);

        public Task<BaseUser?> GetByEmailAsync(string email) =>
            _userManager.FindByEmailAsync(email);

        public Task<IdentityResult> CreateAsync(BaseUser user, string password) =>
            _userManager.CreateAsync(user, password);

        public Task<IdentityResult> UpdateAsync(BaseUser user) =>
            _userManager.UpdateAsync(user);

        public Task<IdentityResult> DeleteAsync(BaseUser user) =>
            _userManager.DeleteAsync(user);

        public Task<bool> CheckPasswordAsync(BaseUser user, string password) =>
            _userManager.CheckPasswordAsync(user, password);

        public Task<string> GenerateEmailConfirmationTokenAsync(BaseUser user) =>
            _userManager.GenerateEmailConfirmationTokenAsync(user);

        public Task<IdentityResult> ConfirmEmailAsync(BaseUser user, string token) =>
            _userManager.ConfirmEmailAsync(user, token);

        public Task<string> GeneratePasswordResetTokenAsync(BaseUser user) =>
            _userManager.GeneratePasswordResetTokenAsync(user);

        public Task<IdentityResult> ResetPasswordAsync(BaseUser user, string token, string newPassword) =>
            _userManager.ResetPasswordAsync(user, token, newPassword);

        public Task<IdentityResult> ChangePasswordAsync(BaseUser user, string current, string newPassword) =>
            _userManager.ChangePasswordAsync(user, current, newPassword);

        public Task<IList<string>> GetRolesAsync(BaseUser user) =>
            _userManager.GetRolesAsync(user);
    }
}
