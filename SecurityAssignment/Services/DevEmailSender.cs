using Microsoft.AspNetCore.Identity.UI.Services;

namespace SecurityAssignment.Services
{
    public class DevEmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            Console.WriteLine("====== DEV EMAIL SENDER ======");
            Console.WriteLine($"To: {email}");
            Console.WriteLine($"Subject: {subject}");
            Console.WriteLine("Message:");
            Console.WriteLine(htmlMessage);
            Console.WriteLine("====== END DEV EMAIL ======");

            return Task.CompletedTask;
        }
    }
}
