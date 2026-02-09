using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecurityAssignment.Data;
using SecurityAssignment.Models;

namespace SecurityAssignment.Services
{
    public class PasswordHistoryService
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;

        public PasswordHistoryService(ApplicationDbContext db, UserManager<ApplicationUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        // Returns true if newPassword matches any of the last N stored hashes
        public async Task<bool> IsReusedAsync(ApplicationUser user, string newPassword, int lastN = 2)
        {
            var lastHashes = await _db.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.ChangedUtc)
                .Take(lastN)
                .Select(p => p.PasswordHash)
                .ToListAsync();

            foreach (var oldHash in lastHashes)
            {
                var verify = _userManager.PasswordHasher.VerifyHashedPassword(user, oldHash, newPassword);
                if (verify == PasswordVerificationResult.Success || verify == PasswordVerificationResult.SuccessRehashNeeded)
                    return true;
            }

            return false;
        }

        // Save current PasswordHash and keep only last N records
        public async Task RecordCurrentHashAsync(ApplicationUser user, int keepLastN = 2)
        {
            // Ensure we have latest user hash
            var freshUser = await _userManager.FindByIdAsync(user.Id);
            if (freshUser == null) return;

            if (string.IsNullOrEmpty(freshUser.PasswordHash)) return;

            _db.PasswordHistories.Add(new PasswordHistory
            {
                UserId = freshUser.Id,
                PasswordHash = freshUser.PasswordHash,
                ChangedUtc = DateTime.UtcNow
            });

            await _db.SaveChangesAsync();

            // Keep only last N
            var all = await _db.PasswordHistories
                .Where(p => p.UserId == freshUser.Id)
                .OrderByDescending(p => p.ChangedUtc)
                .ToListAsync();

            if (all.Count > keepLastN)
            {
                var toDelete = all.Skip(keepLastN).ToList();
                _db.PasswordHistories.RemoveRange(toDelete);
                await _db.SaveChangesAsync();
            }
        }
    }
}
