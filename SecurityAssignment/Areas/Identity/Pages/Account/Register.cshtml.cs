// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using SecurityAssignment.Data;
using SecurityAssignment.Models;
using SecurityAssignment.Services;

namespace SecurityAssignment.Areas.Identity.Pages.Account
{
    public class RegisterModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;
        private readonly CryptoService _crypto;
        private readonly ApplicationDbContext _db;
        private readonly PasswordHistoryService _pwHistory;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender,
            CryptoService crypto,
            ApplicationDbContext db,
            PasswordHistoryService pwHistory)
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _crypto = crypto;
            _db = db;
            _pwHistory = pwHistory;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public class InputModel
        {
            [Required]
            [Display(Name = "First Name")]
            public string FirstName { get; set; }

            [Required]
            [Display(Name = "Last Name")]
            public string LastName { get; set; }

            [Required]
            public string Gender { get; set; }

            [Required]
            [RegularExpression(@"(?i)^[STFGM]\d{7}[A-Z]$", ErrorMessage = "NRIC format invalid (example: S1234567A).")]
            [Display(Name = "NRIC")]
            public string Nric { get; set; }

            [Required]
            [DataType(DataType.Date)]
            [Display(Name = "Date of Birth")]
            public DateTime DateOfBirth { get; set; }

            [Display(Name = "Resume (.pdf or .docx)")]
            public IFormFile Resume { get; set; }

            [Display(Name = "Who Am I")]
            [StringLength(500)]
            public string WhoAmI { get; set; }

            [Required]
            [EmailAddress]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 12)]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
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

        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            Input.Email = Input.Email?.Trim();
            Input.Nric = Input.Nric?.Trim().ToUpperInvariant();

            var existingUser = await _userManager.FindByEmailAsync(Input.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Input.Email", "Email already registered. Please login or use another email.");
                return Page();
            }

            if (!ModelState.IsValid) return Page();

            if (Input.DateOfBirth > DateTime.Today)
            {
                ModelState.AddModelError("Input.DateOfBirth", "Date of Birth cannot be in the future.");
                return Page();
            }

            var user = CreateUser();
            user.FirstName = Input.FirstName;
            user.LastName = Input.LastName;
            user.Gender = Input.Gender;
            user.DateOfBirth = Input.DateOfBirth;
            user.WhoAmI = Input.WhoAmI;
            user.PasswordLastChangedUtc = DateTime.UtcNow;

            user.EncryptedNric = _crypto.Encrypt(Input.Nric);

            if (Input.Resume != null && Input.Resume.Length > 0)
            {
                if (Input.Resume.Length > 2_000_000)
                {
                    ModelState.AddModelError("Input.Resume", "Resume file too large (max 2MB).");
                    return Page();
                }

                var ext = Path.GetExtension(Input.Resume.FileName).ToLowerInvariant();
                var allowedExt = new[] { ".pdf", ".docx" };
                if (!allowedExt.Contains(ext))
                {
                    ModelState.AddModelError("Input.Resume", "Resume must be .pdf or .docx only.");
                    return Page();
                }

                var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", "resumes");
                Directory.CreateDirectory(uploadsFolder);

                var fileName = $"{Guid.NewGuid():N}{ext}";
                var fullPath = Path.Combine(uploadsFolder, fileName);

                using (var stream = new FileStream(fullPath, FileMode.Create))
                {
                    await Input.Resume.CopyToAsync(stream);
                }

                user.ResumePath = $"/uploads/resumes/{fileName}";
            }

            await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
            await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);

            var result = await _userManager.CreateAsync(user, Input.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("User created a new account with password.");
                await WriteAudit(user.Id, "Register Success");

                // Save initial password hash into history (max 2)
                await _pwHistory.RecordCurrentHashAsync(user, keepLastN: 2);

                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                var callbackUrl = Url.Page(
                    "/Account/ConfirmEmail",
                    pageHandler: null,
                    values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                    protocol: Request.Scheme);

                await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                if (_userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                }

                await _signInManager.SignInAsync(user, isPersistent: false);
                return LocalRedirect(returnUrl);
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return Page();
        }

        private ApplicationUser CreateUser()
        {
            try { return Activator.CreateInstance<ApplicationUser>(); }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'.");
            }
        }

        private IUserEmailStore<ApplicationUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
                throw new NotSupportedException("The default UI requires a user store with email support.");

            return (IUserEmailStore<ApplicationUser>)_userStore;
        }
    }
}
