// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecurityAssignment.Data;
using SecurityAssignment.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecurityAssignment.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _db;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            ILogger<LoginModel> logger,
            IConfiguration configuration,
            ApplicationDbContext db)
        {
            _signInManager = signInManager;
            _logger = logger;
            _configuration = configuration;
            _db = db;
        }

        private async Task WriteAudit(string userId, string action)
        {
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = string.IsNullOrWhiteSpace(userId) ? null : userId,
                Action = action,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers.UserAgent.ToString(),
                UtcTime = DateTime.UtcNow
            });

            await _db.SaveChangesAsync();
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            public string CaptchaToken { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // ----- reCAPTCHA v3 verify -----
            var secret = _configuration["Recaptcha:SecretKey"];
            var minScore = double.Parse(_configuration["Recaptcha:MinScore"] ?? "0.5", CultureInfo.InvariantCulture);

            if (string.IsNullOrWhiteSpace(Input.CaptchaToken))
            {
                ModelState.AddModelError(string.Empty, "Captcha token missing.");
                return Page();
            }

            using (var http = new HttpClient())
            {
                var resp = await http.PostAsync(
                    $"https://www.google.com/recaptcha/api/siteverify?secret={secret}&response={Input.CaptchaToken}",
                    null);

                var json = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                var success = doc.RootElement.GetProperty("success").GetBoolean();
                if (!success)
                {
                    ModelState.AddModelError(string.Empty, "Captcha failed.");
                    return Page();
                }

                var score = doc.RootElement.TryGetProperty("score", out var scoreProp) ? scoreProp.GetDouble() : 0.0;
                if (score < minScore)
                {
                    ModelState.AddModelError(string.Empty, "Captcha score too low.");
                    return Page();
                }
            }
            // ----- end reCAPTCHA -----

            var user = await _signInManager.UserManager.FindByEmailAsync(Input.Email);

            var result = await _signInManager.PasswordSignInAsync(
                Input.Email,
                Input.Password,
                Input.RememberMe,
                lockoutOnFailure: true);

            // CRITICAL FIX: Check 2FA FIRST, before any session logic
            if (result.RequiresTwoFactor)
            {
                await WriteAudit(user?.Id ?? "", "Login Requires 2FA");
                // Redirect to 2FA WITHOUT generating session ID
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
            }

            if (result.Succeeded)
            {
                // Initialize password last changed for old users
                if (user != null && user.PasswordLastChangedUtc == default)
                {
                    user.PasswordLastChangedUtc = DateTime.UtcNow;
                    await _signInManager.UserManager.UpdateAsync(user);
                }

                // Password age policy (90 days)
                if (user != null)
                {
                    if ((DateTime.UtcNow - user.PasswordLastChangedUtc).TotalDays > 90)
                    {
                        await _signInManager.SignOutAsync();
                        await WriteAudit(user.Id, "Login Blocked - Password Expired");
                        return RedirectToPage("./ForgotPassword");
                    }
                }

                // Single session enforcement
                // Generate session ID but DON'T refresh sign-in yet
                // Let the middleware add the claim on first request
                if (user != null)
                {
                    user.CurrentSessionId = Guid.NewGuid().ToString("N");
                    await _signInManager.UserManager.UpdateAsync(user);
                }

                _logger.LogInformation("User logged in.");
                await WriteAudit(user?.Id ?? "", "Login Success");
                return LocalRedirect(returnUrl);
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                await WriteAudit(user?.Id ?? "", "Login Locked Out");
                return RedirectToPage("./Lockout");
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            await WriteAudit(user?.Id ?? "", "Login Failed");
            return Page();
        }
    }
}