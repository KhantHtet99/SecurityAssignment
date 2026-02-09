using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecurityAssignment.Data;
using SecurityAssignment.Models;

namespace SecurityAssignment.Pages
{
    [Authorize]
    public class MemberSearchModel : PageModel
    {
        private readonly ApplicationDbContext _db;

        public MemberSearchModel(ApplicationDbContext db)
        {
            _db = db;
        }

        [BindProperty(SupportsGet = true)]
        public string? Email { get; set; }

        public List<ApplicationUser> Results { get; set; } = new();

        public async Task OnGetAsync()
        {
            if (!string.IsNullOrWhiteSpace(Email))
            {
                
                Results = await _db.Users
                    .Where(u => u.Email != null && u.Email.Contains(Email))
                    .Take(20)
                    .ToListAsync();
            }
        }
    }
}
