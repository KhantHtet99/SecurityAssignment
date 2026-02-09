using Microsoft.AspNetCore.Identity;
using SecurityAssignment.Models;

namespace SecurityAssignment.Middleware
{
    public class SingleSessionMiddleware
    {
        private readonly RequestDelegate _next;

        public SingleSessionMiddleware(RequestDelegate next) => _next = next;

        public async Task InvokeAsync(
            HttpContext context,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            var path = context.Request.Path.Value ?? "";

            // Skip Identity pages + errors + static assets
            if (path.StartsWith("/Identity", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/Error", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/css", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/js", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/lib", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/favicon", StringComparison.OrdinalIgnoreCase))
            {
                await _next(context);
                return;
            }

            if (context.User?.Identity?.IsAuthenticated != true)
            {
                await _next(context);
                return;
            }

            var user = await userManager.GetUserAsync(context.User);
            if (user == null)
            {
                await _next(context);
                return;
            }

            var claimSessionId = context.User.Claims
                .FirstOrDefault(c => c.Type == "session_id")?.Value;
            var dbSessionId = user.CurrentSessionId;

            //  DEBUG OUTPUT
            Console.WriteLine("═══════════════════════════════════════");
            Console.WriteLine($"[Middleware] Path: {context.Request.Path}");
            Console.WriteLine($"[Middleware] User: {user.Email}");
            Console.WriteLine($"[Middleware] Claim SessionId: {claimSessionId ?? "NULL"}");
            Console.WriteLine($"[Middleware] DB SessionId: {dbSessionId ?? "NULL"}");
            Console.WriteLine($"[Middleware] Match: {(claimSessionId == dbSessionId ? "TRUE" : "FALSE")}");
            Console.WriteLine("═══════════════════════════════════════");

            // If DB session missing, create it ONCE here (safe), then refresh + redirect once
            if (string.IsNullOrWhiteSpace(dbSessionId))
            {
                Console.WriteLine($"[Middleware] Creating new session for {user.Email}");
                user.CurrentSessionId = Guid.NewGuid().ToString("N");
                await userManager.UpdateAsync(user);
                await signInManager.RefreshSignInAsync(user);
                RedirectOnce(context);
                return;
            }

            // If claim missing OR mismatch, try refresh ONCE (avoid infinite loop)
            if (string.IsNullOrWhiteSpace(claimSessionId) ||
                !string.Equals(claimSessionId, dbSessionId, StringComparison.Ordinal))
            {
                // If we already tried sync once and still mismatch -> sign out
                if (context.Request.Query.ContainsKey("__ssync"))
                {
                    Console.WriteLine($"[Middleware] SESSION MISMATCH - Logging out {user.Email}");
                    await signInManager.SignOutAsync();
                    context.Response.Redirect("/Identity/Account/Login?message=session_expired");
                    return;
                }

                Console.WriteLine($"[Middleware] Refreshing sign-in for {user.Email}");
                await signInManager.RefreshSignInAsync(user);
                RedirectOnce(context);
                return;
            }

            Console.WriteLine($"[Middleware] Session valid - continuing");
            await _next(context);
        }

        private static void RedirectOnce(HttpContext context)
        {
            var req = context.Request;
            var qs = req.QueryString.HasValue ? req.QueryString.Value : "";

            // Add marker to prevent infinite loops
            if (!qs.Contains("__ssync=", StringComparison.OrdinalIgnoreCase))
            {
                qs = string.IsNullOrEmpty(qs) ? "?__ssync=1" : qs + "&__ssync=1";
            }

            var url = req.Path + qs;
            Console.WriteLine($"[Middleware] Redirecting to: {url}");
            context.Response.Redirect(url);
        }
    }
}