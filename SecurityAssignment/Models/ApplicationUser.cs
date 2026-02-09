using Microsoft.AspNetCore.Identity;
using System;

namespace SecurityAssignment.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public string Gender { get; set; } = "";

        // Must be encrypted at rest
        public string? EncryptedNric { get; set; }

        public DateTime DateOfBirth { get; set; }

        // Resume upload (.pdf or .docx)
        public string? ResumePath { get; set; }

        // allow all special characters (Razor auto-encodes on display)
        public string? WhoAmI { get; set; }
        public DateTime PasswordLastChangedUtc { get; set; } = DateTime.UtcNow;
        public bool ForcePasswordChange { get; set; } = false;

        public string? CurrentSessionId { get; set; }

    }
}
