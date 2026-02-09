using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecurityAssignment.Models;
using SecurityAssignment.Services;

namespace SecurityAssignment.Pages
{
    [Authorize]
    public class ProfileModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly CryptoService _crypto;

        public ProfileModel(UserManager<ApplicationUser> userManager, CryptoService crypto)
        {
            _userManager = userManager;
            _crypto = crypto;
        }

        public ApplicationUser? AppUser { get; set; }
        public string? DecryptedNric { get; set; }

        public async Task OnGetAsync()
        {
            AppUser = await _userManager.GetUserAsync(User);

            if (AppUser != null)
            {
                var showNric = Request.Query["showNric"] == "1";
                if (showNric && !string.IsNullOrEmpty(AppUser.EncryptedNric))
                {
                    DecryptedNric = _crypto.Decrypt(AppUser.EncryptedNric);
                }
            }


        }
    }
}
