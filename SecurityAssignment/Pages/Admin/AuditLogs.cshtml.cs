using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecurityAssignment.Data;
using SecurityAssignment.Models;
using Microsoft.AspNetCore.Authorization;

namespace SecurityAssignment.Pages.Admin
{
    [Authorize]
    public class AuditLogsModel : PageModel
    {
        private readonly ApplicationDbContext _db;

        public AuditLogsModel(ApplicationDbContext db)
        {
            _db = db;
        }

        public List<AuditLog> Logs { get; set; } = new();

        public async Task OnGetAsync()
        {
            Logs = await _db.AuditLogs
                .OrderByDescending(x => x.UtcTime)
                .Take(200)
                .ToListAsync();
        }
    }
}
