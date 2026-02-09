using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using SecurityAssignment.Models;
using System.Security.Claims;

namespace SecurityAssignment.Services
{
    public class SessionClaimsFactory : UserClaimsPrincipalFactory<ApplicationUser>
    {
        public SessionClaimsFactory(
            UserManager<ApplicationUser> userManager,
            IOptions<IdentityOptions> optionsAccessor)
            : base(userManager, optionsAccessor)
        {
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
        {
            var identity = await base.GenerateClaimsAsync(user);

            // Remove duplicates if any
            foreach (var c in identity.FindAll("session_id").ToList())
            {
                identity.RemoveClaim(c);
            }

            // Add claim only if DB has one
            if (!string.IsNullOrWhiteSpace(user.CurrentSessionId))
            {
                identity.AddClaim(new Claim("session_id", user.CurrentSessionId));
            }

            return identity;
        }
    }
}
