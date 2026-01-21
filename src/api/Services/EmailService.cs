using Skills.Models;
using Microsoft.AspNetCore.Identity;
using System.Net;
using System.Net.Mail;
using System.Numerics;
using System.Threading.Tasks;


namespace Skills.Services
{
    public interface IEmailService
    {
        Task SendConfirmationEmailAsync(string to, string confirmationLink);
        Task SendPasswordResetEmailAsync(string to, string resetLink);

        Task SendEmailVerificationOtpAsync(string email, string otp);
        Task SendEmailVerificationAsync(string email, string token);
        Task SendPasswordChangeNotificationAsync(ApplicationUser user, string token);
        Task SendUnlockEmailAsync(ApplicationUser user, string token);
        Task SendRecoveryEmailAsync(ApplicationUser user, string token);
        Task SendPasswordResetAsync(string email, string token);
        Task SendWelcomeEmailAsync(string email, string firstName);
        Task SendPropertyApprovedEmailAsync(ApplicationUser owner, Guid propertyId, string propertyTitle);
        Task SendPropertyRejectedEmailAsync(ApplicationUser owner, Guid propertyId, string propertyTitle, string reason);


    }


    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILoggingService _logger;

        public EmailService(IConfiguration configuration, ILoggingService logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendEmailVerificationAsync(string email, string confirmationLink)
        {
            var subject = "Verify Your Email Address";
            var body = $@"
                <h2>Email Verification</h2>
                <p>Thank you for registering with Habitera!</p>
                <p>Please confirm your account by clicking the button below:</p>
                <a href=""{confirmationLink}"" style=""background:#007bff;color:#fff;padding:10px 20px;text-decoration:none;border-radius:5px;"">
                    Confirm Email
                </a>
<p>{confirmationLink}</P
                <p>This link will expire in 10 minutes.</p>
                <p>If you didn't create an account, please ignore this email.</p>
            ";

            await SendEmailAsync(email, subject, body);
        }

        public async Task SendEmailVerificationOtpAsync(string email, string otp)
        {
            var subject = "Verify Your Email Address";
            var body = $@"
        <div style='font-family: Arial, sans-serif; line-height:1.6;'>
            <h2 style='color:#2c3e50;'>Email Verification</h2>
            <p>Thank you for registering with <strong>Habitera</strong>!</p>
            <p>Please use the verification code below to confirm your account:</p>

            <div style='margin:20px 0;'>
                <span style='display:inline-block; padding:10px 20px; font-size:20px; 
                             font-weight:bold; letter-spacing:3px; color:#fff; 
                             background-color:#3498db; border-radius:6px;'>
                    {otp}
                </span>
            </div>

            <p>This code will expire in <strong>10 minutes</strong>.</p>
            <p>If you did not create an account, you can safely ignore this email.</p>
        </div>
    ";

            await SendEmailAsync(email, subject, body);
        }


        //     <p>Please use the following verification code to verify your email address:</p>

        //            <h1 style = 'color: #4CAF50; font-size: 32px; letter-spacing: 5px;' >{token
        //}</h1>

        public async Task SendPasswordChangeNotificationAsync(ApplicationUser user, string token)
        {
            //var token = await _authService.GenerateAccountLockTokenAsync(user);

            var subject = "Password Change Confirmation - Habitera";

            var lockAccountUrl = $"https://habitera.com/account/lock?token={token}";

            var body = $@"
        <div style='font-family: Arial, sans-serif; color: #333;'>
            <h2 style='color: #4CAF50;'>Password Change</h2>
            <p>Stay secure with <strong>Habitera</strong>!</p>

            <p>Please be informed that the password change initiated for your email address:
                <strong>{user.Email}</strong> was</p>

            <h1 style='color: #4CAF50; font-size: 28px; letter-spacing: 3px;'>Successful</h1>

            <p>If <strong>you did not change your password</strong>, please take immediate action:</p>

            <p>
                <a href='{lockAccountUrl}' 
                   style='display:inline-block; padding:10px 20px; background-color:#f44336; color:white; 
                          text-decoration:none; border-radius:5px; font-weight:bold;'>
                   Lock My Account
                </a>
            </p>

            <p style='margin-top:20px;'>
                Or copy and paste this link into your browser:<br/>
                <a href='{lockAccountUrl}'>{lockAccountUrl}</a>
            </p>

            <p style='margin-top:30px; font-size:12px; color:#888;'>
                If this action was performed by you, no further action is required.
            </p>
        </div>
    ";

            if (string.IsNullOrEmpty(user.Email))
            {
                _logger.LogWarning("Cannot send password change notification: user email is null or empty");
                return;
            }

            await SendEmailAsync(user.Email, subject, body);
        }

        public async Task SendUnlockEmailAsync(ApplicationUser user, string token)
        {
            //var token = await _authService.GenerateAccountUnlockTokenAsync(user);

            var subject = "Unlock Your Habitera Account";
            var unlockUrl = $"https://habitera.com/account/unlock?token={token}";

            var body = $@"
        <h2>Unlock Your Account</h2>
        <p>We received a request to unlock your account.</p>
        <p>
            <a href='{unlockUrl}' style='padding:10px 20px; background:#4CAF50; color:white; text-decoration:none;'>
                Unlock My Account
            </a>
        </p>
        <p>If you didn�t request this, please contact support.</p>
    ";

            if (string.IsNullOrEmpty(user.Email))
            {
                _logger.LogWarning("Cannot send unlock email: user email is null or empty");
                return;
            }

            await SendEmailAsync(user.Email, subject, body);
        }

        public async Task SendRecoveryEmailAsync(ApplicationUser user, string token)
        {

            var subject = "Recover Your Habitera Account";
            var recoverUrl = $"https://habitera.com/account/recover?token={token}";

            var body = $@"
        <h2>Recover Your Account</h2>
        <p>We received a request to recover your account.</p>
        <p>
            <a href='{recoverUrl}' style='padding:10px 20px; background:#4CAF50; color:white; text-decoration:none;'>
                Recover My Account
            </a>
        </p>
        <p>If you didn�t request this, please ignore</p>
    ";

            if (string.IsNullOrEmpty(user.Email))
            {
                _logger.LogWarning("Cannot send recovery email: user email is null or empty");
                return;
            }


            await SendEmailAsync(user.Email, subject, body);
        }


        public async Task SendPasswordResetAsync(string email, string token)
        {

            var subject = "Reset Your Password";
            var body = $@"
                <h2>Password Reset Request</h2>
                <p>We received a request to reset your password for your Habitera account.</p>
                <p>Please use the following code to reset your password:</p>
                <h1 style='color: #FF5722; font-size: 32px; letter-spacing: 5px;'>{token}</h1>
                <p>You can also reset your password by clicking this link: </p>
                <h1 style='color: #FF5722; font-size: 32px; letter-spacing: 5px;'>{token}</h1>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't request a password reset, please ignore this email.</p>
            ";

            await SendEmailAsync(email, subject, body);
        }

        public async Task SendPropertyApprovedEmailAsync(ApplicationUser owner, Guid propertyId, string propertyTitle)
        {
            //var user = await _userManager.FindByIdAsync(ownerId);
            if (owner.Email == null)
                return;

            var subject = "Property Listing Approved";
            var body = $@"
                    <h2>Good News!</h2>
                    <p>Dear {owner.FirstName},</p>
                    <p>Your property listing '<strong>{propertyTitle}</strong>' has been approved and is now live on our platform.</p>
                    <p>Property ID: {propertyId}</p>
                    <p>Your listing is now visible to potential buyers/renters.</p>
                    <br/>
                    <p>Best regards,<br/>The Habitera Team</p>
                ";


            await SendEmailAsync(owner.Email, subject, body);
        }

        public async Task SendPropertyRejectedEmailAsync(ApplicationUser owner, Guid propertyId, string propertyTitle, string reason)
        {
            //var user = await _userManager.FindByIdAsync(ownerId);
            if (owner.Email == null)
                return;

            var subject = "Property Listing Requires Attention";
            var body = $@"
                    <h2>Property Listing Update</h2>
                    <p>Dear {owner.FirstName},</p>
                    <p>Your property listing '<strong>{propertyTitle}</strong>' requires some changes before it can be approved.</p>
                    <p>Property ID: {propertyId}</p>
                    <h3>Reason:</h3>
                    <p>{reason}</p>
                    <p>Please review the feedback and make the necessary changes. You can edit and resubmit your listing from your dashboard.</p>
                    <br/>
                    <p>Best regards,<br/>The Habitera Team</p>
                ";


            await SendEmailAsync(owner.Email, subject, body);
        }


        public async Task SendWelcomeEmailAsync(string email, string firstName)
        {
            var subject = "Welcome to Habitera!";
            var body = $@"
                <h2>Welcome to Habitera, {firstName}!</h2>
                <p>Thank you for verifying your email address. You're now ready to start building better habits!</p>
                <p>Here are some things you can do to get started:</p>
                <ul>
                    <li>Create your first habit</li>
                    <li>Set up daily reminders</li>
                    <li>Track your progress</li>
                    <li>Celebrate your achievements</li>
                </ul>
                <p>Happy habit building!</p>
                <p>The Habitera Team</p>
            ";

            await SendEmailAsync(email, subject, body);
        }

        private async Task SendEmailAsync(string to, string subject, string body)
        {
            try
            {
                var smtpServer = _configuration["Brevo:SmtpServer"];
                var smtpPort = int.Parse(_configuration["Brevo:Port"] ?? "587");

                var fromEmail = _configuration["Brevo:FromEmail"];
                var fromName = _configuration["Brevo:FromName"] ?? "Habitera";
                var username = _configuration["Brevo:Username"];
                var password = _configuration["Brevo:Password"];

                if (string.IsNullOrEmpty(fromEmail) || string.IsNullOrEmpty(password))
                {
                    _logger.LogWarning("Brevo email configuration is missing. Required: FromEmail, Username, Password");
                    return;
                }

                using var client = new SmtpClient(smtpServer, smtpPort)
                {
                    Credentials = new NetworkCredential(username, password),
                    EnableSsl = true,
                    DeliveryMethod = SmtpDeliveryMethod.Network
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(fromEmail, fromName),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };

                mailMessage.To.Add(to);

                await client.SendMailAsync(mailMessage);
                _logger.LogInfo($"Email sent successfully via Brevo to: {to}");
            }
            catch (SmtpException smtpEx)
            {
                _logger.LogError($"SMTP error sending email to {to}: {smtpEx.StatusCode} - {smtpEx.Message}");
                throw new Exception("Failed to send email. Please check SMTP settings.");
            }
        }

        //public async Task SendEmailAsync(string to, string subject, string body)
        //{
        //    // TODO: Implement email sending logic (SendGrid, SMTP, etc.)
        //    _logger.LogInfo("Email sending requested", new { To = to, Subject = subject });
        //    await Task.CompletedTask;
        //}

        public async Task SendConfirmationEmailAsync(string to, string confirmationLink)
        {
            var subject = "Confirm Your Email Address";
            var body = $"Please confirm your email by clicking this link: {confirmationLink}";
            await SendEmailAsync(to, subject, body);
        }

        public async Task SendPasswordResetEmailAsync(string to, string resetLink)
        {
            var subject = "Reset Your Password";
            var body = $"Reset your password by clicking this link: {resetLink}";
            await SendEmailAsync(to, subject, body);
        }



    }


    public interface IMailService
    {
        Task SendEmailAsync(string to, string subject, string htmlBody);
    }

    public class MailService : IMailService
    {
        private readonly string _smtpHost = "smtp.mailtrap.io";
        private readonly int _smtpPort = 587;
        private readonly string _smtpUser = "<your_mailtrap_username>";
        private readonly string _smtpPass = "<your_mailtrap_password>";
        private readonly IConfiguration _configuration;
        private readonly ILoggingService _logger;

        public MailService(IConfiguration configuration, ILoggingService logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendEmailAsync(string to, string subject, string htmlBody)
        {

            var smtpHost = _configuration["MailTrap:Host"];
            var smtpPort = int.Parse(_configuration["MailTrap:Port"] ?? "587");

            var fromEmail = _configuration["MailTrap:FromEmail"] ?? "noreply@skills.com";
            var fromName = _configuration["MailTrap:FromName"] ?? "Skills";
            var smtpUser = _configuration["MailTrap:Username"];
            var smtpPass = _configuration["MailTrap:Password"];

            using var client = new SmtpClient(smtpHost, smtpPort)
            {
                Credentials = new NetworkCredential(smtpUser, smtpPass),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(fromEmail, fromName),
                Subject = subject,
                Body = htmlBody,
                IsBodyHtml = true
            };

            mailMessage.To.Add(to);

            //await client.SendMailAsync(mailMessage);
            client.Send(mailMessage);

            //await client.Send(fromEmail, to, subject, htmlBody)
        }
    }

}