// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SecurityAssignment.Data;
using SecurityAssignment.Models;
using SecurityAssignment.Services;

namespace SecurityAssignment.Areas.Identity.Pages.Account.Manage
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;
        private readonly ApplicationDbContext _db;
        private readonly PasswordHistoryService _pwHistory;

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<ChangePasswordModel> logger,
            ApplicationDbContext db,
            PasswordHistoryService pwHistory)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _db = db;
            _pwHistory = pwHistory;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        [TempData]
        public string StatusMessage { get; set; }

        public class InputModel
        {
            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Current password")]
            public string OldPassword { get; set; }

            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 12)]
            [DataType(DataType.Password)]
            [Display(Name = "New password")]
            public string NewPassword { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm new password")]
            [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        private async Task WriteAudit(string userId, string action)
        {
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = userId,
                Action = action,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers.UserAgent.ToString(),
                UtcTime = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword)
                return RedirectToPage("./SetPassword");

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

            // 1) Min password age (24h)
            if ((DateTime.UtcNow - user.PasswordLastChangedUtc).TotalMinutes < 1 )
            {
                ModelState.AddModelError(string.Empty, "You can only change password once every 24 hours.");
                await WriteAudit(user.Id, "Change Password Blocked - Min Age");
                return Page();
            }

            // 2) Password reuse check (last 2)
            if (await _pwHistory.IsReusedAsync(user, Input.NewPassword, lastN: 2))
            {
                ModelState.AddModelError(string.Empty, "You cannot reuse your last 2 passwords.");
                await WriteAudit(user.Id, "Change Password Blocked - Password Reuse");
                return Page();
            }

            // Record old hash before changing (so it becomes history)
            await _pwHistory.RecordCurrentHashAsync(user, keepLastN: 2);

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, Input.OldPassword, Input.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                await WriteAudit(user.Id, "Change Password Failed");
                return Page();
            }

            // 3) Update password age timestamp on success
            user.PasswordLastChangedUtc = DateTime.UtcNow;
            user.ForcePasswordChange = false;
            await _userManager.UpdateAsync(user);

            // Record new hash after change
            await _pwHistory.RecordCurrentHashAsync(user, keepLastN: 2);

            await _signInManager.RefreshSignInAsync(user);
            _logger.LogInformation("User changed their password successfully.");
            await WriteAudit(user.Id, "Change Password Success");

            StatusMessage = "Your password has been changed.";
            return RedirectToPage();
        }
    }
}
