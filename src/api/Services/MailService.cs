using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using static System.Net.WebRequestMethods;

namespace Skills.Services
{
    public interface IGMailService
    {
        Task SendEmailVerificationAsync(string email, string token);

    }

    public class GMailService : IGMailService
    {

        private readonly IConfiguration _configuration;
        private readonly ILoggingService _logger;

        public GMailService(IConfiguration configuration, ILoggingService logger)
        {
            _configuration = configuration;
            _logger = logger;
        }


        public async Task SendEmailVerificationAsync(string email, string token)
        {
            var subject = "Verify Your Email Address";
            var body = $@"
        <div style='font-family: Arial, sans-serif; line-height:1.6;'>
            <h2 style='color:#2c3e50;'>Email Verification</h2>
            <p>Thank you for registering with <strong>Skills</strong>!</p>
            <p>Please use the verification code below to confirm your account:</p>

            <div style='margin:20px 0;'>
                <span style='display:inline-block; padding:10px 20px; font-size:20px; 
                             font-weight:bold; letter-spacing:3px; color:#fff; 
                             background-color:#3498db; border-radius:6px;'>
                    {token}
                </span>
            </div>

            <p>This code will expire in <strong>10 minutes</strong>.</p>
            <p>If you did not create an account, you can safely ignore this email.</p>
        </div>
    ";

            await SendEmailViaGmailAsync(email, subject, body);
        }



        private async Task SendEmailViaGmailAsync(string to, string subject, string body)
        {
            try
            {
                var smtpServer = _configuration["Gmail:SmtpServer"] ?? "smtp.gmail.com";
                var smtpPort = int.Parse(_configuration["Gmail:Port"] ?? "587");

                var fromEmail = _configuration["Gmail:FromEmail"];
                var fromName = _configuration["Gmail:FromName"] ?? "Habitera";
                var username = _configuration["Gmail:Username"];
                var password = _configuration["Gmail:Password"];

                if (string.IsNullOrWhiteSpace(fromEmail) ||
                    string.IsNullOrWhiteSpace(username) ||
                    string.IsNullOrWhiteSpace(password))
                {
                    _logger.LogWarning(
                        "Gmail email configuration is missing. Required: FromEmail, Username, Password");
                    return;
                }

                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(fromName, fromEmail));
                message.To.Add(MailboxAddress.Parse(to));
                message.Subject = subject;

                message.Body = new BodyBuilder
                {
                    HtmlBody = body
                }.ToMessageBody();

                using var client = new SmtpClient();

                await client.ConnectAsync(
                    smtpServer,
                    smtpPort,
                    SecureSocketOptions.StartTls);

                await client.AuthenticateAsync(username, password);
                await client.SendAsync(message);
                await client.DisconnectAsync(true);

                _logger.LogInfo($"Email sent successfully via Gmail (MailKit) to: {to}");
            }
            catch (MailKit.Security.AuthenticationException authEx)
            {
                _logger.LogError("Failed to generate and send verification code", authEx, "Gmail authentication failed");
                throw new Exception("Gmail authentication failed. Check App Password.");
            }
            catch (SmtpCommandException smtpEx)
            {
                _logger.LogError("Failed to generate and send verification code",
                    smtpEx,
                    $"SMTP command error sending email via Gmail to {to}: {smtpEx.StatusCode}");

                throw new Exception("SMTP command failed while sending email.");
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to generate and send verification code", ex, $"Unexpected error sending email via Gmail to {to}");
                throw;
            }
        }

    }
}