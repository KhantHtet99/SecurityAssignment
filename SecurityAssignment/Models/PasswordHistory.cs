using System;

namespace SecurityAssignment.Models
{
    public class PasswordHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public DateTime ChangedUtc { get; set; } = DateTime.UtcNow;
    }
}
