
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Skills.Data;
using Skills.DTOs;
using Skills.Models;
using Skills.Services;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Skills.Services
{
    public interface IAuthenticationService
    {
        Task<AuthResult> RegisterAsync(RegisterRequest request);
        Task<AuthResult> LoginAsync(LoginRequest request);
        Task<AuthResult> EmailVerifyAsync(VerifyEmailRequest request);
        Task<AuthResult> ResendVerificationCodeEndpointAsync(ResendCodeRequest request);
        Task<AuthResult> RefreshTokenAsync(string refreshToken);
    }

    public class AuthenticationService : IAuthenticationService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IGMailService _mailService;
        private readonly ILoggingService _logger;

        // Configuration constants
        private const int MAX_LOGIN_ATTEMPTS = 5;
        private const int LOCKOUT_DURATION_MINUTES = 15;
        private const int VERIFICATION_CODE_LENGTH = 6;
        private const int MAX_VERIFICATION_ATTEMPTS = 3;
        private const int RATE_LIMIT_SECONDS = 60;
        private const int MAX_ACTIVE_REFRESH_TOKENS_PER_DEVICE = 5;

        // NEW: IP-based rate limiting constants
        private const int IP_LOGIN_MAX_ATTEMPTS = 20;
        private const int IP_LOGIN_WINDOW_MINUTES = 15;
        private const int IP_REGISTRATION_MAX_ATTEMPTS = 5;
        private const int IP_REGISTRATION_WINDOW_MINUTES = 60;
        private const int PENDING_LOGIN_RESEND_MAX = 3;
        private const int SUSPICIOUS_ACCOUNT_THRESHOLD = 10;
        private const int SUSPICIOUS_ACTIVITY_WINDOW_MINUTES = 30;

        public AuthenticationService(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            AppDbContext context,
            IConfiguration configuration,
            IEmailService emailService,
            IGMailService mailService,
            ILoggingService loggingService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _context = context;
            _configuration = configuration;
            _emailService = emailService;
            _mailService = mailService;
            _logger = loggingService;

            ValidateConfiguration();
        }

        public async Task<AuthResult> RegisterAsync(RegisterRequest request)
        {
            var correlationId = Guid.NewGuid().ToString();
            var overallTimer = Stopwatch.StartNew();

            try
            {
                _logger.LogInfo("Registration attempt started",
                    new { CorrelationId = correlationId, Email = request.Email });

                // IP rate limit check
                var ipRateLimit = await CheckIpRateLimit(
                    request.IpAddress,
                    "Registration",
                    IP_REGISTRATION_MAX_ATTEMPTS,
                    IP_REGISTRATION_WINDOW_MINUTES,
                    correlationId);

                if (ipRateLimit != null)
                {
                    await LogAuditAsync(null, "Registration", request.IpAddress, null,
                        false, "IP rate limit exceeded", correlationId);
                    return ipRateLimit;
                }

                // Validate input
                var validationResult = ValidateUserRegistrationInput(request);
                if (!validationResult.IsValid)
                {
                    return AuthResult.Failure(validationResult.ErrorMessage);
                }

                var normalizedEmail = NormalizeEmail(request.Email);
                var sanitizedPhone = SanitizePhoneNumber(request.PhoneNumber);

                // ===== USE EXECUTION STRATEGY INSTEAD OF MANUAL TRANSACTION =====
                var strategy = _context.Database.CreateExecutionStrategy();

                return await strategy.ExecuteAsync(async () =>
                {
                    await using var transaction = await _context.Database.BeginTransactionAsync();

                    try
                    {
                        // Check existing user
                        var existingUser = await _context.Users
                            .FirstOrDefaultAsync(u => u.Email == normalizedEmail);

                        if (existingUser != null)
                        {
                            await transaction.RollbackAsync();
                            return await HandleExistingUserRegistration(existingUser, request, correlationId);
                        }

                        // Check phone uniqueness
                        var phoneExists = await _context.Users
                            .AnyAsync(u => u.PhoneNumber == sanitizedPhone);

                        if (phoneExists)
                        {
                            await transaction.RollbackAsync();
                            return AuthResult.Failure("User with this phone number already exists");
                        }

                        // Create user and related data
                        var (result, user) = await CreateNewUser(
                            request,
                            normalizedEmail,
                            sanitizedPhone,
                            correlationId);

                        if (!result || user == null || string.IsNullOrWhiteSpace(user.Email))
                        {
                            await transaction.RollbackAsync();
                            return AuthResult.Failure("Error occurred creating user");
                        }

                        await _context.SaveChangesAsync();
                        await transaction.CommitAsync();

                        _logger.LogInfo("User registration transaction completed", new
                        {
                            CorrelationId = correlationId,
                            UserId = user.Id,
                            DurationMs = overallTimer.ElapsedMilliseconds
                        });

                        // Fire and forget email sending
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await GenerateAndSendVerificationCodeAsync(user.Id, user.Email, correlationId);
                                _logger.LogInfo("Verification email sent successfully", new
                                {
                                    CorrelationId = correlationId,
                                    UserId = user.Id
                                });
                            }
                            catch (Exception emailEx)
                            {
                                _logger.LogError("Background verification email failed", emailEx, new
                                {
                                    CorrelationId = correlationId,
                                    UserId = user.Id
                                });
                            }
                        });

                        // Log audit
                        await LogAuditAsync(
                            user.Id,
                            "Registration",
                            null,
                            null,
                            true,
                            $"User registered as {request.UserType} - pending verification",
                            correlationId);

                        _logger.LogInfo("User registration completed", new
                        {
                            CorrelationId = correlationId,
                            UserId = user.Id,
                            TotalDurationMs = overallTimer.ElapsedMilliseconds
                        });

                        return AuthResult.PendingVerification(
                            user.Id,
                            user.Email,
                            "Registration successful. Please check your email for the verification code."
                        );
                    }
                    catch (Exception transactionEx)
                    {
                        await transaction.RollbackAsync();
                        _logger.LogError("Transaction failed during registration", transactionEx,
                            new { CorrelationId = correlationId, Email = normalizedEmail });
                        throw;
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError("Registration failed", ex, new
                {
                    CorrelationId = correlationId,
                    Email = request.Email,
                    DurationMs = overallTimer.ElapsedMilliseconds
                });
                return AuthResult.Failure("Registration failed. Please try again later.");
            }
        }
        public async Task<AuthResult> RegisterOldAsync(RegisterRequest request)
        {
            var correlationId = Guid.NewGuid().ToString();

            try
            {
                _logger.LogInfo("Registration attempt started", new { CorrelationId = correlationId, Email = request.Email });

                // NEW: Check IP-based rate limiting for registrations
                var ipRateLimit = await CheckIpRateLimit(
                    request.IpAddress,
                    "Registration",
                    IP_REGISTRATION_MAX_ATTEMPTS,
                    IP_REGISTRATION_WINDOW_MINUTES,
                    correlationId);

                if (ipRateLimit != null)
                {
                    await LogAuditAsync(null, "Registration", request.IpAddress, null,
                        false, "IP rate limit exceeded", correlationId);
                    return ipRateLimit;
                }

                // Validate input with enhanced validation
                var validationResult = ValidateUserRegistrationInput(request);
                if (!validationResult.IsValid)
                {
                    _logger.LogWarning("Registration validation failed", new { CorrelationId = correlationId, Error = validationResult.ErrorMessage });
                    return AuthResult.Failure(validationResult.ErrorMessage);
                }

                var normalizedEmail = NormalizeEmail(request.Email);
                var sanitizedPhone = SanitizePhoneNumber(request.PhoneNumber);

                // ENHANCED: Use serializable transaction to prevent race conditions
                await using var transaction = await _context.Database.BeginTransactionAsync(
                    System.Data.IsolationLevel.Serializable);

                try
                {
                    // Check existing user with transaction isolation
                    var existingUser = await _context.Users
                        .Where(u => u.Email == normalizedEmail)
                        .FirstOrDefaultAsync();

                    if (existingUser != null)
                    {
                        await transaction.CommitAsync();
                        return await HandleExistingUserRegistration(existingUser, request, correlationId);
                    }

                    // Check phone uniqueness
                    var phoneExists = await _context.Users.AnyAsync(u => u.PhoneNumber == sanitizedPhone);
                    if (phoneExists)
                    {
                        await transaction.CommitAsync();
                        _logger.LogWarning("Registration failed - phone exists", new { CorrelationId = correlationId });
                        return AuthResult.Failure("User with this phone number already exists");
                    }

                    var result = await CreateNewUser(request, normalizedEmail, sanitizedPhone, correlationId);
                    await transaction.CommitAsync();
                    //return result;
                    return AuthResult.Failure("User with this phone number already exists");

                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Registration failed", ex, new { CorrelationId = correlationId, Email = request.Email });
                return AuthResult.Failure("Registration failed. Please try again later.");
            }
        }

        public async Task<AuthResult> LoginAsync(LoginRequest request)
        {
            var correlationId = Guid.NewGuid().ToString();

            try
            {
                _logger.LogInfo("Login attempt started", new { CorrelationId = correlationId, Email = request.Email, IpAddress = request.IpAddress });

                // NEW: Check IP-based rate limiting
                var ipRateLimit = await CheckIpRateLimit(
                    request.IpAddress,
                    "LoginAttempt",
                    IP_LOGIN_MAX_ATTEMPTS,
                    IP_LOGIN_WINDOW_MINUTES,
                    correlationId);

                if (ipRateLimit != null)
                {
                    await LogAuditAsync(null, "LoginAttempt", request.IpAddress, request.UserAgent,
                        false, "IP rate limit exceeded", correlationId);
                    return ipRateLimit;
                }

                // NEW: Check for suspicious activity patterns
                if (await DetectSuspiciousActivity(request.IpAddress, request.UserAgent, correlationId))
                {
                    await LogAuditAsync(null, "LoginAttempt", request.IpAddress, request.UserAgent,
                        false, "Suspicious activity detected", correlationId);
                    // Still allow login but log for monitoring
                }

                var normalizedEmail = NormalizeEmail(request.Email);
                var user = await _userManager.FindByEmailAsync(normalizedEmail);

                if (user == null)
                {
                    // Prevent email enumeration - consistent response time
                    await Task.Delay(Random.Shared.Next(100, 300));
                    _logger.LogWarning("Login failed - user not found", new { CorrelationId = correlationId, Email = normalizedEmail });

                    // Still log for IP rate limiting
                    await LogAuditAsync(null, "LoginAttempt", request.IpAddress, request.UserAgent,
                        false, "User not found", correlationId);

                    return AuthResult.Failure("Invalid email or password");
                }

                // ENHANCED: Check if account is locked - DO THIS BEFORE PASSWORD VALIDATION
                var lockoutCheck = await CheckAndHandleLockout(user, request.IpAddress, correlationId);
                if (lockoutCheck != null)
                {
                    return lockoutCheck; // Early exit - don't validate password or process further
                }

                // NEW: Apply exponential backoff for repeated failures
                var delay = await CalculateLoginDelay(user.Id);
                if (delay > 0)
                {
                    await Task.Delay(delay);
                }

                // Validate password
                var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
                if (!passwordValid)
                {
                    await HandleFailedLoginAttempt(user, request.IpAddress, request.UserAgent, correlationId);
                    return AuthResult.Failure("Invalid email or password");
                }

                // Check if account is inactive
                if (!user.IsActive)
                {
                    _logger.LogWarning("Login failed - account inactive", new { CorrelationId = correlationId, UserId = user.Id });
                    return AuthResult.Failure("Account is inactive. Please contact support.");
                }

                // Handle pending/unverified accounts
                if (user.Status == UserStatus.Pending)
                {
                    return await HandlePendingAccountLogin(user, request, correlationId);
                }

                // Check other non-active statuses
                if (user.Status != UserStatus.Active)
                {
                    _logger.LogWarning("Login failed - account status issue", new { CorrelationId = correlationId, UserId = user.Id, Status = user.Status });
                    return AuthResult.Failure($"Account is {user.Status.ToString().ToLower()}. Please contact support.");
                }

                // Successful login - cleanup old refresh tokens
                await CleanupOldRefreshTokens(user.Id, request.DeviceInfo);

                // Update last login
                user.LastLoginAt = DateTime.UtcNow;
                user.UpdatedAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                // Generate tokens
                var accessToken = GenerateAccessToken(user);
                var refreshToken = await GenerateRefreshTokenAsync(user.Id, request.DeviceInfo, request.IpAddress);

                // Log successful login
                await LogAuditAsync(user.Id, "Login", request.IpAddress, request.UserAgent, true, "Successful login", correlationId);
                _logger.LogInfo("Login successful", new { CorrelationId = correlationId, UserId = user.Id });

                return AuthResult.Success(accessToken, refreshToken, user);
            }
            catch (Exception ex)
            {
                _logger.LogError("Login failed with exception", ex, new { CorrelationId = correlationId, Email = request.Email });
                return AuthResult.Failure("Login failed. Please try again later.");
            }
        }

        public async Task<AuthResult> EmailVerifyAsync(VerifyEmailRequest request)
        {
            var correlationId = Guid.NewGuid().ToString();

            try
            {
                _logger.LogInfo("Email verification attempt started", new { CorrelationId = correlationId, Email = request.Email });

                var normalizedEmail = NormalizeEmail(request.Email);
                var user = await _userManager.FindByEmailAsync(normalizedEmail);

                if (user == null)
                {
                    _logger.LogWarning("Email verification failed - user not found", new { CorrelationId = correlationId, Email = normalizedEmail });
                    return AuthResult.Failure("Invalid verification request");
                }

                if (user.EmailVerified)
                {
                    _logger.LogInfo("Email verification attempted on already verified account", new { CorrelationId = correlationId, UserId = user.Id });
                    return AuthResult.Failure("Email already verified. Please login.");
                }

                if (user.Status != UserStatus.Pending)
                {
                    _logger.LogInfo("Email verification attempted on non-pending account", new { CorrelationId = correlationId, UserId = user.Id });
                    return AuthResult.Failure("User is not new. Please register or login.");
                }

                // Check verification attempts to prevent brute force
                var tooManyAttempts = await CheckVerificationAttempts(user.Id, normalizedEmail, correlationId, request.IpAddress);
                if (tooManyAttempts != null)
                {
                    return tooManyAttempts;
                }

                // Find the verification token
                var verificationToken = await _context.EmailVerificationTokens
                    .Where(t => t.Email == normalizedEmail &&
                            t.TokenHash == request.Code &&
                            !t.Used &&
                            t.ExpiresAt > DateTime.UtcNow)
                    .OrderByDescending(t => t.CreatedAt)
                    .FirstOrDefaultAsync();

                if (verificationToken == null)
                {
                    await RecordFailedVerificationAttempt(user.Id, normalizedEmail);

                    // Check if code is expired
                    var expiredToken = await _context.EmailVerificationTokens
                        .Where(t => t.Email == normalizedEmail &&
                                t.TokenHash == request.Code &&
                                !t.Used)
                        .FirstOrDefaultAsync();

                    if (expiredToken != null)
                    {
                        _logger.LogWarning("Email verification failed - code expired", new { CorrelationId = correlationId, UserId = user.Id });
                        return AuthResult.Failure("Verification code has expired. Please request a new one.");
                    }

                    _logger.LogWarning("Email verification failed - invalid code", new { CorrelationId = correlationId, UserId = user.Id });
                    return AuthResult.Failure("Invalid verification code");
                }

                await using var transaction = await _context.Database.BeginTransactionAsync();

                try
                {
                    // Mark token as used
                    verificationToken.Used = true;
                    verificationToken.UsedAt = DateTime.UtcNow;

                    // Update user status
                    user.EmailVerified = true;
                    user.Status = UserStatus.Active;
                    user.UpdatedAt = DateTime.UtcNow;

                    await _context.SaveChangesAsync();
                    await transaction.CommitAsync();

                    // Log audit
                    await LogAuditAsync(user.Id, "EmailVerification", null, null, true, "Email verified successfully", correlationId);
                    _logger.LogInfo("Email verification successful", new { CorrelationId = correlationId, UserId = user.Id });

                    // Generate tokens for authenticated session
                    var accessToken = GenerateAccessToken(user);
                    var refreshToken = await GenerateRefreshTokenAsync(user.Id, request.DeviceInfo, request.IpAddress);

                    return AuthResult.Success(accessToken, refreshToken, user);
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    _logger.LogError("Email verification transaction failed", ex, new { CorrelationId = correlationId, UserId = user.Id });
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Email verification failed", ex, new { CorrelationId = correlationId, Email = request.Email });
                return AuthResult.Failure("Verification failed. Please try again.");
            }
        }

        public async Task<AuthResult> ResendVerificationCodeEndpointAsync(ResendCodeRequest request)
        {
            var correlationId = Guid.NewGuid().ToString();

            try
            {
                _logger.LogInfo("Resend verification code attempt", new { CorrelationId = correlationId, Email = request.Email });

                // NEW: Check IP-based rate limiting
                var ipRateLimit = await CheckIpRateLimit(
                    request.IpAddress,
                    "ResendVerification",
                    maxAttempts: 10,
                    windowMinutes: 60,
                    correlationId);

                if (ipRateLimit != null)
                {
                    await LogAuditAsync(null, "ResendVerification", request.IpAddress, null,
                        false, "IP rate limit exceeded", correlationId);
                    return ipRateLimit;
                }

                var normalizedEmail = NormalizeEmail(request.Email);
                var user = await _userManager.FindByEmailAsync(normalizedEmail);

                if (user == null)
                {
                    // Don't reveal that user doesn't exist
                    await Task.Delay(Random.Shared.Next(100, 300));
                    _logger.LogWarning("Resend code attempted for non-existent user", new { CorrelationId = correlationId, Email = normalizedEmail });
                    return AuthResult.Failure("If an account exists with this email, a verification code has been sent.");
                }

                if (user.EmailVerified || user.Status != UserStatus.Pending)
                {
                    _logger.LogInfo("Resend code attempted for non-pending account", new { CorrelationId = correlationId, UserId = user.Id });
                    return AuthResult.Failure("Email already verified. Please login.");
                }

                if (string.IsNullOrWhiteSpace(user.Email))
                {
                    _logger.LogError("User account has no email", null, new { CorrelationId = correlationId, UserId = user.Id });
                    return AuthResult.Failure("Invalid account configuration. Please contact support.");
                }

                // Check rate limiting
                var rateLimitCheck = await CheckResendRateLimit(user.Id, user.Email);
                if (!rateLimitCheck.Succeeded)
                {
                    _logger.LogWarning("Resend code rate limited", new { CorrelationId = correlationId, UserId = user.Id });
                    return AuthResult.Failure(rateLimitCheck.Message);
                }

                var result = await ResendVerificationCodeAsync(user.Id, user.Email, correlationId);
                if (!result.Succeeded)
                {
                    return AuthResult.Failure(result.Message);
                }

                _logger.LogInfo("Verification code resent successfully", new { CorrelationId = correlationId, UserId = user.Id });

                return AuthResult.PendingVerification(
                    userId: user.Id,
                    email: user.Email,
                    message: "Verification code has been resent to your email."
                );
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to resend verification code", ex, new { CorrelationId = correlationId, Email = request.Email });
                return AuthResult.Failure("Failed to send verification code. Please try again later.");
            }
        }

        public async Task<AuthResult> RefreshTokenAsync(string refreshToken)
        {
            var correlationId = Guid.NewGuid().ToString();

            try
            {
                _logger.LogInfo("Token refresh attempt", new { CorrelationId = correlationId });

                var tokenHash = HashToken(refreshToken);
                var storedToken = await _context.RefreshTokens
                    .Include(t => t.User)
                    .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && !t.Revoked);

                if (storedToken == null)
                {
                    _logger.LogWarning("Token refresh failed - invalid token", new { CorrelationId = correlationId });
                    return AuthResult.Failure("Invalid refresh token");
                }

                if (storedToken.ExpiresAt < DateTime.UtcNow)
                {
                    storedToken.Revoked = true;
                    storedToken.RevokedAt = DateTime.UtcNow;
                    storedToken.RevokedReason = "Token expired";
                    await _context.SaveChangesAsync();

                    _logger.LogWarning("Token refresh failed - token expired", new { CorrelationId = correlationId, UserId = storedToken.UserId });
                    return AuthResult.Failure("Refresh token expired. Please login again.");
                }

                var user = storedToken.User;
                if (!user.IsActive || user.Status != UserStatus.Active)
                {
                    _logger.LogWarning("Token refresh failed - user inactive", new { CorrelationId = correlationId, UserId = user.Id });
                    return AuthResult.Failure("Account is not active. Please contact support.");
                }

                // Generate new tokens
                var accessToken = GenerateAccessToken(user);
                var newRefreshToken = await GenerateRefreshTokenAsync(user.Id, storedToken.DeviceInfo, storedToken.IpAddress);

                // Revoke old refresh token
                storedToken.Revoked = true;
                storedToken.RevokedAt = DateTime.UtcNow;
                storedToken.RevokedReason = "Token refreshed";
                await _context.SaveChangesAsync();

                _logger.LogInfo("Token refresh successful", new { CorrelationId = correlationId, UserId = user.Id });

                return AuthResult.Success(accessToken, newRefreshToken, user);
            }
            catch (Exception ex)
            {
                _logger.LogError("Token refresh failed", ex, new { CorrelationId = correlationId });
                return AuthResult.Failure("Token refresh failed. Please login again.");
            }
        }


        private void ValidateConfiguration()
        {
            var errors = new List<string>();

            // Validate JWT settings
            var jwtKey = _configuration["JwtSettings:SecretKey"];
            if (string.IsNullOrWhiteSpace(jwtKey))
                errors.Add("JwtSettings:SecretKey is missing");
            else if (jwtKey.Length < 32)
                errors.Add("JwtSettings:SecretKey must be at least 32 characters long");

            if (string.IsNullOrWhiteSpace(_configuration["JwtSettings:Issuer"]))
                errors.Add("JwtSettings:Issuer is missing");

            if (string.IsNullOrWhiteSpace(_configuration["JwtSettings:Audience"]))
                errors.Add("JwtSettings:Audience is missing");

            var expiryMinutes = _configuration["JwtSettings:ExpiryMinutes"];
            if (string.IsNullOrWhiteSpace(expiryMinutes) || !int.TryParse(expiryMinutes, out var expiry) || expiry <= 0)
                errors.Add("JwtSettings:ExpiryMinutes must be a positive integer");

            var refreshTokenDays = _configuration["JwtSettings:RefreshTokenExpiryDays"];
            if (!string.IsNullOrWhiteSpace(refreshTokenDays) && (!int.TryParse(refreshTokenDays, out var days) || days <= 0))
                errors.Add("JwtSettings:RefreshTokenExpiryDays must be a positive integer");

            if (errors.Any())
            {
                var errorMessage = $"Configuration validation failed: {string.Join("; ", errors)}";
                _logger.LogError(errorMessage, null, new { Errors = errors });
                throw new InvalidOperationException(errorMessage);
            }

            _logger.LogInfo("Configuration validation successful", new { });
        }

        private async Task<AuthResult?> CheckIpRateLimit(
            string? ipAddress,
            string action,
            int maxAttempts,
            int windowMinutes,
            string correlationId)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return null;

            var windowStart = DateTime.UtcNow.AddMinutes(-windowMinutes);

            var ipAttempts = await _context.AuditLogs
                .Where(l => l.IpAddress == ipAddress &&
                       l.Action == action &&
                       l.CreatedAt >= windowStart)
                .CountAsync();

            if (ipAttempts >= maxAttempts)
            {
                _logger.LogWarning($"IP rate limit exceeded for {action}",
                    new { CorrelationId = correlationId, IpAddress = ipAddress, Attempts = ipAttempts });

                return AuthResult.Failure(
                    "Too many requests from this IP address. Please try again later.");
            }

            return null;
        }

        private async Task<bool> DetectSuspiciousActivity(
            string? ipAddress,
            string? userAgent,
            string correlationId)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            var windowStart = DateTime.UtcNow.AddMinutes(-SUSPICIOUS_ACTIVITY_WINDOW_MINUTES);

            // Check for attempts against multiple accounts from same IP
            var distinctUsers = await _context.AuditLogs
                .Where(l => l.IpAddress == ipAddress &&
                       l.Action == "LoginAttempt" &&
                       l.CreatedAt >= windowStart)
                .Select(l => l.UserId)
                .Distinct()
                .CountAsync();

            if (distinctUsers > SUSPICIOUS_ACCOUNT_THRESHOLD)
            {
                _logger.LogWarning("Suspicious activity detected - possible account enumeration",
                    new
                    {
                        CorrelationId = correlationId,
                        IpAddress = ipAddress,
                        DistinctAccounts = distinctUsers,
                        WindowMinutes = SUSPICIOUS_ACTIVITY_WINDOW_MINUTES
                    });
                return true;
            }

            return false;
        }

        private async Task<int> CalculateLoginDelay(string userId)
        {
            var recentFailures = await _context.AuditLogs
                .Where(l => l.UserId == userId &&
                       l.Action == "LoginAttempt" &&
                       !l.Success &&
                       l.CreatedAt > DateTime.UtcNow.AddMinutes(-5))
                .CountAsync();

            // Exponential backoff: 0, 1, 2, 4, 8 seconds (capped at 8)
            return recentFailures > 0 ? (int)Math.Pow(2, Math.Min(recentFailures - 1, 3)) * 1000 : 0;
        }



        // ============================================================================
        // PRIVATE HELPER METHODS
        // ============================================================================

        private async Task<AuthResult> HandleExistingUserRegistration(ApplicationUser existingUser, RegisterRequest request, string correlationId)
        {
            if (existingUser.EmailVerified)
            {
                _logger.LogWarning("Registration attempted for verified account", new { CorrelationId = correlationId, UserId = existingUser.Id });
                return AuthResult.Failure("An account with this email already exists. Please login.");
            }

            if (string.IsNullOrWhiteSpace(existingUser.Email))
            {
                _logger.LogError("Existing user has no email", null, new { CorrelationId = correlationId, UserId = existingUser.Id });
                return AuthResult.Failure("Invalid account configuration. Please contact support.");
            }

            await using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                // Update user information
                existingUser.FirstName = SanitizeInput(request.FirstName, 50);
                existingUser.LastName = SanitizeInput(request.LastName, 50);
                existingUser.PhoneNumber = SanitizePhoneNumber(request.PhoneNumber);
                existingUser.UserType = request.UserType;
                existingUser.UpdatedAt = DateTime.UtcNow;

                // Update password
                var removePasswordResult = await _userManager.RemovePasswordAsync(existingUser);
                if (removePasswordResult.Succeeded)
                {
                    var addPasswordResult = await _userManager.AddPasswordAsync(existingUser, request.Password);
                    if (!addPasswordResult.Succeeded)
                    {
                        _logger.LogWarning("Password update failed during registration update", new { CorrelationId = correlationId, UserId = existingUser.Id });
                        return AuthResult.Failure("Failed to update password");
                    }
                }

                // Update role if needed
                await UpdateUserRole(existingUser, request.UserType);

                // Update type-specific data
                await UpdateUserTypeSpecificData(existingUser, request);

                await _context.SaveChangesAsync();

                // Resend verification code
                var resendResult = await ResendVerificationCodeAsync(existingUser.Id, existingUser.Email, correlationId);
                if (!resendResult.Succeeded)
                {
                    await transaction.RollbackAsync();
                    return AuthResult.Failure("Failed to send verification code. Please try again.");
                }

                await transaction.CommitAsync();

                await LogAuditAsync(existingUser.Id, "RegistrationUpdate", null, null, true,
                    $"User updated registration details as {request.UserType} - verification code resent", correlationId);

                _logger.LogInfo("Existing user registration updated", new { CorrelationId = correlationId, UserId = existingUser.Id });

                return AuthResult.PendingVerification(
                    userId: existingUser.Id,
                    email: existingUser.Email,
                    message: "Your registration details have been updated. A verification code has been sent to your email."
                );
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError("Transaction failed during registration update", ex, new { CorrelationId = correlationId, UserId = existingUser.Id });
                throw;
            }
        }

        private async Task<(bool Result, ApplicationUser? User)> CreateNewUser(
    RegisterRequest request,
    string normalizedEmail,
    string sanitizedPhone,
    string correlationId)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                // Validate role exists (with caching)
                var roleName = request.UserType.ToString();
                if (!await RoleExistsAsync(request.UserType))
                {
                    _logger.LogError("Role does not exist", null,
                        new { CorrelationId = correlationId, Role = roleName });
                    return (false, null);
                }

                // Create user
                var user = new ApplicationUser
                {
                    UserName = normalizedEmail,
                    Email = normalizedEmail,
                    FirstName = SanitizeInput(request.FirstName, 50),
                    LastName = SanitizeInput(request.LastName, 50),
                    PhoneNumber = sanitizedPhone,
                    UserType = request.UserType,
                    Status = UserStatus.Pending,
                    EmailVerified = false,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                _logger.LogDebug("Creating user account", new
                {
                    CorrelationId = correlationId,
                    Email = normalizedEmail
                });

                var createResult = await _userManager.CreateAsync(user, request.Password);
                if (!createResult.Succeeded)
                {
                    var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
                    _logger.LogWarning("User creation failed", new
                    {
                        CorrelationId = correlationId,
                        Email = normalizedEmail,
                        Errors = errors,
                        DurationMs = sw.ElapsedMilliseconds
                    });
                    return (false, null);
                }

                _logger.LogDebug("User account created, assigning role", new
                {
                    CorrelationId = correlationId,
                    UserId = user.Id,
                    Role = roleName
                });

                // Assign role
                var roleResult = await _userManager.AddToRoleAsync(user, roleName);
                if (!roleResult.Succeeded)
                {
                    var errors = string.Join(", ", roleResult.Errors.Select(e => e.Description));
                    _logger.LogError("Role assignment failed", null, new
                    {
                        CorrelationId = correlationId,
                        UserId = user.Id,
                        Role = roleName,
                        Errors = errors,
                        DurationMs = sw.ElapsedMilliseconds
                    });

                    // Cleanup: delete the user since role assignment failed
                    await _userManager.DeleteAsync(user);
                    return (false, null);
                }

                _logger.LogDebug("Role assigned, creating type-specific data", new
                {
                    CorrelationId = correlationId,
                    UserId = user.Id,
                    UserType = request.UserType
                });

                // Create all type-specific data in a single transaction
                await CreateUserTypeSpecificDataOptimized(user, request, correlationId);

                // Single SaveChanges for all related entities
                await _context.SaveChangesAsync();

                _logger.LogInfo("User creation completed successfully", new
                {
                    CorrelationId = correlationId,
                    UserId = user.Id,
                    UserType = request.UserType,
                    DurationMs = sw.ElapsedMilliseconds
                });

                return (true, user);
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception during user creation", ex, new
                {
                    CorrelationId = correlationId,
                    Email = normalizedEmail,
                    DurationMs = sw.ElapsedMilliseconds
                });
                return (false, null);
            }
        }


        private async Task CreateUserTypeSpecificDataOptimized(
            ApplicationUser user,
            RegisterRequest request,
            string correlationId)
        {
            if (request.UserType == UserType.User)
            {
                // Store user service preferences
                if (request.ServicePreferences?.Any() == true)
                {
                    var validPreferences = request.ServicePreferences
                        .Where(sp => !string.IsNullOrWhiteSpace(sp))
                        .Distinct()
                        .Select(sp => new ServicePreference
                        {
                            UserId = user.Id,
                            ServiceCategory = SanitizeInput(sp, 100) ?? sp,
                            CreatedAt = DateTime.UtcNow
                        })
                        .ToList();

                    if (validPreferences.Any())
                    {
                        _context.ServicePreferences.AddRange(validPreferences);
                        _logger.LogDebug("Added {Count} service preferences", new
                        {
                            CorrelationId = correlationId,
                            UserId = user.Id,
                            Count = validPreferences.Count
                        });
                    }
                }
            }
            else if (request.UserType == UserType.Artisan)
            {
                // Create artisan profile
                var artisanProfile = new ArtisanProfile
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    BusinessName = SanitizeInput(request.BusinessName, 100),
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                _context.ArtisanProfiles.Add(artisanProfile);

                _logger.LogDebug("Created artisan profile", new
                {
                    CorrelationId = correlationId,
                    UserId = user.Id,
                    ProfileId = artisanProfile.Id
                });

                // NOTE: We need to save here to get the artisan profile ID
                // for the foreign key relationship with Service
                await _context.SaveChangesAsync();

                // Add artisan's first service (if provided)
                if (request.Service != null)
                {
                    var service = new Service
                    {
                        Id = Guid.NewGuid(),
                        ArtisanId = artisanProfile.Id,
                        Name = SanitizeInput(request.Service.Name, 100) ?? request.Service.Name,
                        Category = request.Service.Category,
                        PricingModel = request.Service.PricingModel,
                        MinPrice = request.Service.MinPrice,
                        MaxPrice = request.Service.MaxPrice,
                        Availability = request.Service.Availability,
                        Notes = SanitizeInput(request.Service.Notes, 500),
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };

                    _context.Services.Add(service);

                    _logger.LogDebug("Added artisan service", new
                    {
                        CorrelationId = correlationId,
                        UserId = user.Id,
                        ServiceId = service.Id,
                        ServiceName = service.Name
                    });
                }
            }
        }

        // Role caching helper
        private static readonly ConcurrentDictionary<UserType, bool> _roleExistsCache = new();
        private static readonly SemaphoreSlim _roleCacheLock = new(1, 1);

        private async Task<bool> RoleExistsAsync(UserType userType)
        {
            // Check cache first
            if (_roleExistsCache.TryGetValue(userType, out var exists))
            {
                return exists;
            }

            // Use lock to prevent multiple concurrent checks for the same role
            await _roleCacheLock.WaitAsync();
            try
            {
                // Double-check after acquiring lock
                if (_roleExistsCache.TryGetValue(userType, out exists))
                {
                    return exists;
                }

                var roleName = userType.ToString();
                exists = await _roleManager.RoleExistsAsync(roleName);

                // Cache the result
                _roleExistsCache.TryAdd(userType, exists);

                _logger.LogDebug("Role existence cached", new
                {
                    Role = roleName,
                    Exists = exists
                });

                return exists;
            }
            finally
            {
                _roleCacheLock.Release();
            }
        }

        private async Task<(bool Result, ApplicationUser? User)> CreateNewUserOld(
    RegisterRequest request,
    string normalizedEmail,
    string sanitizedPhone,
    string correlationId)
        {
            var user = new ApplicationUser
            {
                UserName = normalizedEmail,
                Email = normalizedEmail,
                FirstName = request.FirstName,
                LastName = request.LastName,
                PhoneNumber = sanitizedPhone,
                UserType = request.UserType,
                Status = UserStatus.Pending,
                EmailVerified = false,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            var createResult = await _userManager.CreateAsync(user, request.Password);
            if (!createResult.Succeeded)
            {
                var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
                _logger.LogWarning("User creation failed",
                    new { CorrelationId = correlationId, Email = normalizedEmail, Errors = errors });

                //return (AuthResult.Failure(errors), null);
                return (false, null);
            }

            var roleName = request.UserType.ToString();
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                

                _logger.LogError("Role does not exist", null,
                    new { CorrelationId = correlationId, Role = roleName });

                //return (AuthResult.Failure("Invalid role configuration. Please contact support."), null);
                return (false, null);

            }

            var roleResult = await _userManager.AddToRoleAsync(user, roleName);
            if (!roleResult.Succeeded)
            {
                _logger.LogError("Role assignment failed", null,
                    new { CorrelationId = correlationId, UserId = user.Id, Role = roleName });

                //return (AuthResult.Failure("Failed to assign user role"), null);
                return (false, null);
            }

            // Artisan / user-type specific data (still atomic)
            await CreateUserTypeSpecificData(user, request);

            //return (AuthResult.Success(), user);
            return (true, user);
        }


        private async Task<AuthResult?> CheckAndHandleLockout(ApplicationUser user, string? ipAddress, string correlationId)
        {
            var failedAttempts = await _context.AuditLogs
                .Where(l => l.UserId == user.Id &&
                       l.Action == "LoginAttempt" &&
                       !l.Success &&
                       l.CreatedAt > DateTime.UtcNow.AddMinutes(-LOCKOUT_DURATION_MINUTES))
                .CountAsync();

            if (failedAttempts >= MAX_LOGIN_ATTEMPTS)
            {
                var oldestFailedAttempt = await _context.AuditLogs
                    .Where(l => l.UserId == user.Id &&
                           l.Action == "LoginAttempt" &&
                           !l.Success)
                    .OrderByDescending(l => l.CreatedAt)
                    .Skip(MAX_LOGIN_ATTEMPTS - 1)
                    .FirstOrDefaultAsync();

                if (oldestFailedAttempt != null)
                {
                    var lockoutTimeRemaining = LOCKOUT_DURATION_MINUTES - (int)(DateTime.UtcNow - oldestFailedAttempt.CreatedAt).TotalMinutes;

                    if (lockoutTimeRemaining > 0)
                    {
                        _logger.LogWarning("Login attempt on locked account", new { CorrelationId = correlationId, UserId = user.Id, RemainingMinutes = lockoutTimeRemaining });

                        await LogAuditAsync(user.Id, "LoginAttempt", ipAddress, null, false,
                            $"Account locked - {lockoutTimeRemaining} minutes remaining", correlationId);

                        // NEW: Add delay to prevent timing attacks
                        await Task.Delay(Random.Shared.Next(1000, 2000));

                        return AuthResult.Failure($"Account is temporarily locked due to multiple failed login attempts. Please try again in {lockoutTimeRemaining} minutes.");
                    }
                }
            }

            return null;
        }

        private async Task<AuthResult> HandlePendingAccountLogin(ApplicationUser user, LoginRequest request, string correlationId)
        {
            if (string.IsNullOrWhiteSpace(user.Email))
            {
                _logger.LogError("Pending account has no email", null, new { CorrelationId = correlationId, UserId = user.Id });
                return AuthResult.Failure("Invalid account configuration. Please contact support.");
            }

            // NEW: Check rate limiting for pending account login attempts (prevents DDOS)
            var recentPendingLoginAttempts = await _context.AuditLogs
                .Where(l => l.UserId == user.Id &&
                       l.Action == "LoginAttempt" &&
                       l.Details != null && l.Details.Contains("pending verification") &&
                       l.CreatedAt > DateTime.UtcNow.AddMinutes(-LOCKOUT_DURATION_MINUTES))
                .CountAsync();

            if (recentPendingLoginAttempts >= PENDING_LOGIN_RESEND_MAX)
            {
                var oldestAttempt = await _context.AuditLogs
                    .Where(l => l.UserId == user.Id &&
                           l.Action == "LoginAttempt" &&
                           l.Details != null && l.Details.Contains("pending verification"))
                    .OrderByDescending(l => l.CreatedAt)
                    .Skip(PENDING_LOGIN_RESEND_MAX - 1)
                    .FirstOrDefaultAsync();

                if (oldestAttempt != null)
                {
                    var lockoutRemaining = LOCKOUT_DURATION_MINUTES -
                        (int)(DateTime.UtcNow - oldestAttempt.CreatedAt).TotalMinutes;

                    if (lockoutRemaining > 0)
                    {
                        _logger.LogWarning("Pending account login rate limited",
                            new { CorrelationId = correlationId, UserId = user.Id, RemainingMinutes = lockoutRemaining });

                        await LogAuditAsync(user.Id, "LoginAttempt", request.IpAddress,
                            request.UserAgent, false,
                            $"Rate limited - {lockoutRemaining} minutes remaining",
                            correlationId);

                        return AuthResult.Failure(
                            $"Too many verification attempts. Please try again in {lockoutRemaining} minutes.");
                    }
                }
            }

            // NEW: Also check per-user resend rate limit (prevents rapid successive calls)
            var rateLimitCheck = await CheckResendRateLimit(user.Id, user.Email);
            if (!rateLimitCheck.Succeeded)
            {
                await LogAuditAsync(user.Id, "LoginAttempt", request.IpAddress,
                    request.UserAgent, false, rateLimitCheck.Message, correlationId);
                return AuthResult.Failure(rateLimitCheck.Message);
            }

            var verificationResult = await ResendVerificationCodeAsync(user.Id, user.Email, correlationId);
            if (!verificationResult.Succeeded)
            {
                _logger.LogWarning("Failed to resend verification during login", new { CorrelationId = correlationId, UserId = user.Id });
                return AuthResult.Failure("Account pending verification, but failed to send verification code. Please try again.");
            }

            await LogAuditAsync(user.Id, "LoginAttempt", request.IpAddress, request.UserAgent, false,
                "Login attempted - account pending verification, code resent", correlationId);

            _logger.LogInfo("Pending account login handled", new { CorrelationId = correlationId, UserId = user.Id });

            return AuthResult.PendingVerification(
                userId: user.Id,
                email: user.Email,
                message: "Your account is pending email verification. A new verification code has been sent to your email."
            );
        }

        private async Task HandleFailedLoginAttempt(ApplicationUser user, string? ipAddress, string? userAgent, string correlationId)
        {
            await LogAuditAsync(user.Id, "LoginAttempt", ipAddress, userAgent, false, "Invalid password", correlationId);

            var recentFailedAttempts = await _context.AuditLogs
                .Where(l => l.UserId == user.Id &&
                       l.Action == "LoginAttempt" &&
                       !l.Success &&
                       l.CreatedAt > DateTime.UtcNow.AddMinutes(-LOCKOUT_DURATION_MINUTES))
                .CountAsync();

            _logger.LogWarning("Failed login attempt", new
            {
                CorrelationId = correlationId,
                UserId = user.Id,
                FailedAttempts = recentFailedAttempts + 1,
                RemainingAttempts = MAX_LOGIN_ATTEMPTS - (recentFailedAttempts + 1)
            });
        }

        // ============================================================================
        // VERIFICATION & CODE MANAGEMENT
        // ============================================================================

        private async Task<AuthResult?> CheckVerificationAttempts(
            string userId,
            string email,
            string correlationId,
            string? ipAddress)
        {
            var windowStart = DateTime.UtcNow.AddMinutes(-LOCKOUT_DURATION_MINUTES);

            var failedAttemptsQuery = _context.AuditLogs
                .Where(l =>
                    l.UserId == userId &&
                    l.Action == "EmailVerification" &&
                    !l.Success &&
                    l.CreatedAt >= windowStart);

            var failedAttempts = await failedAttemptsQuery.CountAsync();

            if (failedAttempts < MAX_VERIFICATION_ATTEMPTS)
                return null;

            var earliestFailedAttempt = await failedAttemptsQuery
                .OrderBy(l => l.CreatedAt)
                .FirstAsync();

            var lockoutEndsAt = earliestFailedAttempt.CreatedAt
                .AddMinutes(LOCKOUT_DURATION_MINUTES);

            var remainingMinutes = (int)Math.Ceiling(
                (lockoutEndsAt - DateTime.UtcNow).TotalMinutes);

            if (remainingMinutes > 0)
            {
                _logger.LogWarning(
                    "Email verification attempt on locked account",
                    new
                    {
                        CorrelationId = correlationId,
                        UserId = userId,
                        RemainingMinutes = remainingMinutes
                    });

                return AuthResult.Failure(
                    $"Too many verification attempts. Please try again in {remainingMinutes} minutes.");
            }

            return null;
        }

        private async Task RecordFailedVerificationAttempt(string userId, string email)
        {
            await LogAuditAsync(userId, "EmailVerification", null, null, false, "Invalid verification code");
        }

        private async Task<OperationResult> CheckResendRateLimit(string userId, string email)
        {
            var recentToken = await _context.EmailVerificationTokens
                .Where(t => t.UserId == userId && !t.Used)
                .OrderByDescending(t => t.CreatedAt)
                .FirstOrDefaultAsync();

            if (recentToken != null && recentToken.CreatedAt.AddSeconds(RATE_LIMIT_SECONDS) > DateTime.UtcNow)
            {
                var waitTime = (int)(RATE_LIMIT_SECONDS - (DateTime.UtcNow - recentToken.CreatedAt).TotalSeconds);
                _logger.LogWarning("Resend verification code rate limited", new { UserId = userId, WaitSeconds = waitTime });
                return OperationResult.Failure($"Please wait {waitTime} seconds before retrying");
                //return OperationResult.Failure($"Please wait {waitTime} seconds before requesting a new code");
            }

            return OperationResult.Success();
        }

        private async Task<OperationResult> GenerateAndSendVerificationCodeAsync(string userId, string email, string? correlationId = null)
        {
            try
            {
                // Generate cryptographically secure 6-digit code
                var code = GenerateSecureVerificationCode();
                var expiryMinutes = 15;
                var expiryTime = DateTime.UtcNow.AddMinutes(expiryMinutes);

                // Invalidate any previous unused codes for this user
                var existingTokens = await _context.EmailVerificationTokens
                    .Where(t => t.Email == email && !t.Used)
                    .ToListAsync();

                foreach (var token in existingTokens)
                {
                    token.Used = true;
                    token.UsedAt = DateTime.UtcNow;
                }

                // Store verification code
                var verificationToken = new EmailVerificationToken
                {
                    UserId = userId,
                    Email = email,
                    TokenHash = code,
                    ExpiresAt = expiryTime,
                    Used = false,
                    CreatedAt = DateTime.UtcNow
                };

                _context.EmailVerificationTokens.Add(verificationToken);
                await _context.SaveChangesAsync();

                // Send email with verification code
                //await _emailService.SendEmailVerificationAsync(email, code);
                await _mailService.SendEmailVerificationAsync(email, code);

                _logger.LogInfo("Verification code generated and sent", new
                {
                    CorrelationId = correlationId,
                    UserId = userId,
                    ExpiryMinutes = expiryMinutes
                });

                return OperationResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to generate and send verification code", ex, new
                {
                    CorrelationId = correlationId,
                    UserId = userId
                });
                return OperationResult.Failure("Failed to send verification code");
            }
        }

        private async Task<OperationResult> ResendVerificationCodeAsync(string userId, string email, string? correlationId = null)
        {
            try
            {
                // Rate limiting is checked by the caller
                var result = await GenerateAndSendVerificationCodeAsync(userId, email, correlationId);

                if (result.Succeeded)
                {
                    await LogAuditAsync(userId, "VerificationCodeResent", null, null, true, "Verification code resent", correlationId);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to resend verification code", ex, new
                {
                    CorrelationId = correlationId,
                    UserId = userId
                });
                return OperationResult.Failure("Failed to send verification code");
            }
        }

        private string GenerateSecureVerificationCode()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            var number = BitConverter.ToUInt32(bytes, 0);
            return (number % 1000000).ToString("D6");
        }

        // ============================================================================
        // TOKEN GENERATION & MANAGEMENT
        // ============================================================================

        private async Task CleanupOldRefreshTokens(string userId, string? deviceInfo)
        {
            if (string.IsNullOrWhiteSpace(deviceInfo))
                return;

            var now = DateTime.UtcNow;

            var tokensToRevoke = await _context.RefreshTokens
                .Where(t =>
                    t.UserId == userId &&
                    t.DeviceInfo == deviceInfo &&
                    !t.Revoked &&
                    t.ExpiresAt > now)
                .ToListAsync();

            if (tokensToRevoke.Count == 0)
                return;

            foreach (var token in tokensToRevoke)
            {
                token.Revoked = true;
                token.RevokedAt = now;
                token.RevokedReason = "Superseded by new login";
            }

            await _context.SaveChangesAsync();
        }

        private string GenerateAccessToken(ApplicationUser user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"]!));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim("userType", user.UserType.ToString()),
                new Claim("fullName", user.FullName),
                new Claim("emailVerified", user.EmailVerified.ToString()),
                new Claim("status", user.Status.ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["JwtSettings:ExpiryMinutes"])),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<string> GenerateRefreshTokenAsync(string userId, string? deviceInfo, string? ipAddress)
        {
            var token = GenerateSecureToken();
            var tokenHash = HashToken(token);

            var refreshToken = new RefreshToken
            {
                UserId = userId,
                TokenHash = tokenHash,
                DeviceInfo = SanitizeInput(deviceInfo, 200),
                IpAddress = ipAddress,
                ExpiresAt = DateTime.UtcNow.AddDays(Convert.ToDouble(_configuration["JwtSettings:RefreshTokenExpiryDays"] ?? "30")),
                CreatedAt = DateTime.UtcNow
            };

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            return token;
        }

        private string GenerateSecureToken()
        {
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes);
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashBytes);
        }

        // ============================================================================
        // USER TYPE-SPECIFIC DATA MANAGEMENT
        // ============================================================================

        private async Task UpdateUserRole(ApplicationUser user, UserType newUserType)
        {
            var currentRoles = await _userManager.GetRolesAsync(user);
            var newRoleName = newUserType.ToString();

            if (!await _roleManager.RoleExistsAsync(newRoleName))
            {
                throw new InvalidOperationException($"Role {newRoleName} does not exist");
            }

            if (!currentRoles.Contains(newRoleName))
            {
                if (currentRoles.Any())
                {
                    await _userManager.RemoveFromRolesAsync(user, currentRoles);
                }
                var roleResult = await _userManager.AddToRoleAsync(user, newRoleName);
                if (!roleResult.Succeeded)
                {
                    throw new InvalidOperationException("Failed to assign user role");
                }
            }
        }

        private async Task UpdateUserTypeSpecificData(ApplicationUser user, RegisterRequest request)
        {
            if (request.UserType == UserType.User)
            {
                // Remove old artisan profile and services if switching from Artisan to User
                var oldArtisanProfile = await _context.ArtisanProfiles
                    .FirstOrDefaultAsync(ap => ap.UserId == user.Id);

                if (oldArtisanProfile != null)
                {
                    var oldServices = await _context.Services
                        .Where(s => s.ArtisanId == oldArtisanProfile.Id)
                        .ToListAsync();

                    _context.Services.RemoveRange(oldServices);
                    _context.ArtisanProfiles.Remove(oldArtisanProfile);

                    _logger.LogInfo("Removed artisan profile during type switch", new { UserId = user.Id });
                }

                // Remove old preferences
                var oldPreferences = await _context.ServicePreferences
                    .Where(sp => sp.UserId == user.Id)
                    .ToListAsync();
                _context.ServicePreferences.RemoveRange(oldPreferences);

                // Add new preferences
                if (request.ServicePreferences?.Any() == true)
                {
                    var newPreferences = request.ServicePreferences.Select(sp => new ServicePreference
                    {
                        UserId = user.Id,
                        ServiceCategory = sp,
                        CreatedAt = DateTime.UtcNow
                    }).ToList();
                    _context.ServicePreferences.AddRange(newPreferences);
                }
            }
            else if (request.UserType == UserType.Artisan)
            {
                // Remove old service preferences if switching from User to Artisan
                var oldPreferences = await _context.ServicePreferences
                    .Where(sp => sp.UserId == user.Id)
                    .ToListAsync();
                _context.ServicePreferences.RemoveRange(oldPreferences);

                // Update or create artisan profile
                var existingProfile = await _context.ArtisanProfiles
                    .FirstOrDefaultAsync(ap => ap.UserId == user.Id);

                if (existingProfile != null)
                {
                    existingProfile.BusinessName = SanitizeInput(request.BusinessName, 100);
                    existingProfile.UpdatedAt = DateTime.UtcNow;

                    // Remove old services
                    var oldServices = await _context.Services
                        .Where(s => s.ArtisanId == existingProfile.Id)
                        .ToListAsync();
                    _context.Services.RemoveRange(oldServices);
                }
                else
                {
                    existingProfile = new ArtisanProfile
                    {
                        UserId = user.Id,
                        BusinessName = SanitizeInput(request.BusinessName, 100),
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };
                    _context.ArtisanProfiles.Add(existingProfile);
                    await _context.SaveChangesAsync(); // Save to get the profile ID
                }

                // Add new service
                if (request.Service != null)
                {
                    var service = new Service
                    {
                        ArtisanId = existingProfile.Id,
                        Name = SanitizeInput(request.Service.Name, 100),
                        Category = request.Service.Category,
                        PricingModel = request.Service.PricingModel,
                        MinPrice = request.Service.MinPrice,
                        MaxPrice = request.Service.MaxPrice,
                        Availability = request.Service.Availability,
                        Notes = SanitizeInput(request.Service.Notes, 500),
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };
                    _context.Services.Add(service);
                }
            }
        }

        private async Task CreateUserTypeSpecificData(ApplicationUser user, RegisterRequest request)
        {
            if (request.UserType == UserType.User)
            {
                // Store user service preferences
                if (request.ServicePreferences?.Any() == true)
                {
                    var userPreferences = request.ServicePreferences.Select(sp => new ServicePreference
                    {
                        UserId = user.Id,
                        ServiceCategory = sp,
                        CreatedAt = DateTime.UtcNow
                    }).ToList();

                    _context.ServicePreferences.AddRange(userPreferences);
                }
            }
            else if (request.UserType == UserType.Artisan)
            {
                // Create artisan profile
                var artisanProfile = new ArtisanProfile
                {
                    UserId = user.Id,
                    BusinessName = SanitizeInput(request.BusinessName, 100),
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };
                _context.ArtisanProfiles.Add(artisanProfile);
                await _context.SaveChangesAsync(); // Save to get profile ID

                // Add artisan's first service
                if (request.Service != null)
                {
                    var service = new Service
                    {
                        ArtisanId = artisanProfile.Id,
                        Name = SanitizeInput(request.Service.Name, 100),
                        Category = request.Service.Category,
                        PricingModel = request.Service.PricingModel,
                        MinPrice = request.Service.MinPrice,
                        MaxPrice = request.Service.MaxPrice,
                        Availability = request.Service.Availability,
                        Notes = SanitizeInput(request.Service.Notes, 500),
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };
                    _context.Services.Add(service);
                }
            }
        }

        // ============================================================================
        // INPUT VALIDATION & SANITIZATION
        // ============================================================================

        private ValidationResult ValidateUserRegistrationInput(RegisterRequest request)
        {
            // Email validation
            if (string.IsNullOrWhiteSpace(request.Email))
                return new ValidationResult(false, "Email address is required");

            if (!new EmailAddressAttribute().IsValid(request.Email))
                return new ValidationResult(false, "Please provide a valid email address");

            if (request.Email.Length > 254) // RFC 5321
                return new ValidationResult(false, "Email address is too long");

            // Password validation
            if (string.IsNullOrWhiteSpace(request.Password))
                return new ValidationResult(false, "Password is required");

            var passwordValidation = ValidatePassword(request.Password);
            if (!passwordValidation.IsValid)
                return passwordValidation;

            // Name validation
            if (string.IsNullOrWhiteSpace(request.FirstName))
                return new ValidationResult(false, "First name is required");

            if (request.FirstName.Length > 50)
                return new ValidationResult(false, "First name is too long (maximum 50 characters)");

            if (!IsValidName(request.FirstName))
                return new ValidationResult(false, "First name contains invalid characters");

            if (string.IsNullOrWhiteSpace(request.LastName))
                return new ValidationResult(false, "Last name is required");

            if (request.LastName.Length > 50)
                return new ValidationResult(false, "Last name is too long (maximum 50 characters)");

            if (!IsValidName(request.LastName))
                return new ValidationResult(false, "Last name contains invalid characters");

            // Phone validation
            if (string.IsNullOrWhiteSpace(request.PhoneNumber))
                return new ValidationResult(false, "Phone number is required");

            if (!IsValidPhoneNumber(request.PhoneNumber))
                return new ValidationResult(false, "Please provide a valid phone number");

            // UserType validation
            if (!Enum.IsDefined(typeof(UserType), request.UserType))
                return new ValidationResult(false, "Invalid user type");

            if (request.UserType == UserType.User)
            {
                if (request.ServicePreferences == null ||
                    !request.ServicePreferences.Any(p => !string.IsNullOrWhiteSpace(p)))
                {
                    return new ValidationResult(
                        false,
                        "At least one service preference is required for user registration"
                    );
                }
            }

            // Artisan-specific validation
            if (request.UserType == UserType.Artisan)
            {
                if (string.IsNullOrWhiteSpace(request.BusinessName))
                    return new ValidationResult(false, "Business name is required for artisan registration");

                if (request.BusinessName.Length > 100)
                    return new ValidationResult(false, "Business name is too long (maximum 100 characters)");

                if (request.Service == null)
                    return new ValidationResult(false, "At least one service is required for artisan registration");

                // Service validation
                if (string.IsNullOrWhiteSpace(request.Service.Name))
                    return new ValidationResult(false, "Service name is required");

                if (request.Service.Name.Length > 100)
                    return new ValidationResult(false, "Service name is too long (maximum 100 characters)");

                if (string.IsNullOrWhiteSpace(request.Service.Category))
                    return new ValidationResult(false, "Service category is required");

                if (!Enum.IsDefined(typeof(PricingModel), request.Service.PricingModel))
                    return new ValidationResult(false, "Valid pricing model is required");

                if (request.Service.MinPrice < 0)
                    return new ValidationResult(false, "Minimum price cannot be negative");

                if (request.Service.MaxPrice.HasValue && request.Service.MaxPrice < request.Service.MinPrice)
                    return new ValidationResult(false, "Maximum price cannot be less than minimum price");

                if (!string.IsNullOrWhiteSpace(request.Service.Notes) && request.Service.Notes.Length > 500)
                    return new ValidationResult(false, "Service notes are too long (maximum 500 characters)");
            }

            return new ValidationResult(true);
        }

        private ValidationResult ValidatePassword(string password)
        {
            if (password.Length < 8)
                return new ValidationResult(false, "Password must be at least 8 characters long");

            if (password.Length > 128)
                return new ValidationResult(false, "Password is too long (maximum 128 characters)");

            var hasUpper = password.Any(char.IsUpper);
            var hasLower = password.Any(char.IsLower);
            var hasDigit = password.Any(char.IsDigit);
            var hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));

            var strengthScore = 0;
            if (hasUpper) strengthScore++;
            if (hasLower) strengthScore++;
            if (hasDigit) strengthScore++;
            if (hasSpecial) strengthScore++;

            if (strengthScore < 3)
                return new ValidationResult(false, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters");

            // Check for common passwords (simplified - in production use a proper list)
            var commonPasswords = new[] { "password", "12345678", "password123", "qwerty123" };
            if (commonPasswords.Any(cp => password.ToLower().Contains(cp)))
                return new ValidationResult(false, "Password is too common. Please choose a stronger password");

            return new ValidationResult(true);
        }

        private bool IsValidName(string name)
        {
            // Allow letters, spaces, hyphens, apostrophes
            return Regex.IsMatch(name, @"^[a-zA-Z\s\-']+$");
        }

        private bool IsValidPhoneNumber(string phoneNumber)
        {
            // Remove common formatting characters
            var cleaned = Regex.Replace(phoneNumber, @"[\s\-\(\)\+]", "");

            // Check if it's all digits and reasonable length
            return Regex.IsMatch(cleaned, @"^\d{10,15}$");
        }

        private string NormalizeEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return email;

            var trimmed = email.Trim().ToLowerInvariant();

            // Handle Gmail-specific normalization (remove dots and plus aliases)
            if (trimmed.EndsWith("@gmail.com") || trimmed.EndsWith("@googlemail.com"))
            {
                var parts = trimmed.Split('@');
                var localPart = parts[0];

                // Remove dots
                localPart = localPart.Replace(".", "");

                // Remove everything after +
                var plusIndex = localPart.IndexOf('+');
                if (plusIndex > 0)
                {
                    localPart = localPart.Substring(0, plusIndex);
                }

                trimmed = $"{localPart}@gmail.com";
            }

            return trimmed;
        }

        private string SanitizePhoneNumber(string? phoneNumber)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber))
                return phoneNumber ?? string.Empty;

            // Remove all formatting characters, keep only digits and +
            return Regex.Replace(phoneNumber.Trim(), @"[^\d\+]", "");
        }

        private string? SanitizeInput(string? input, int maxLength)
        {
            if (string.IsNullOrWhiteSpace(input))
                return input;

            // Trim and limit length
            var sanitized = input.Trim();
            if (sanitized.Length > maxLength)
            {
                sanitized = sanitized.Substring(0, maxLength);
            }

            // Remove potential XSS/injection characters
            sanitized = sanitized
                .Replace("<", "")
                .Replace(">", "")
                .Replace("'", "'");

            return sanitized;
        }

        // ============================================================================
        // AUDIT LOGGING
        // ============================================================================

        private async Task LogAuditAsync(string? userId, string action, string? ipAddress,
            string? userAgent, bool success, string? details, string? correlationId = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    UserId = userId,
                    Action = action,
                    IpAddress = ipAddress,
                    UserAgent = SanitizeInput(userAgent, 500),
                    Success = success,
                    Details = SanitizeInput(details, 1000),
                    CreatedAt = DateTime.UtcNow
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();

                _logger.LogInfo("Audit log created", new
                {
                    CorrelationId = correlationId,
                    UserId = userId,
                    Action = action,
                    Success = success
                });
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to create audit log", ex, new
                {
                    CorrelationId = correlationId,
                    UserId = userId,
                    Action = action
                });
                // Don't throw - audit logging failure shouldn't break the flow
            }
        }

        // ============================================================================
        // HELPER CLASSES
        // ============================================================================

        private class ValidationResult
        {
            public bool IsValid { get; }
            public string ErrorMessage { get; }

            public ValidationResult(bool isValid, string? errorMessage = null)
            {
                IsValid = isValid;
                ErrorMessage = errorMessage ?? string.Empty;
            }
        }

        public class OperationResult
        {
            public bool Succeeded { get; }
            public string Message { get; }

            private OperationResult(bool succeeded, string message = "")
            {
                Succeeded = succeeded;
                Message = message;
            }

            public static OperationResult Success(string message = "") => new OperationResult(true, message);
            public static OperationResult Failure(string message) => new OperationResult(false, message);
        }
    }


}


//namespace Skills.Services
//{
//    public interface IAuthenticationService
//    {
//        Task<AuthResult> RegisterAsync(RegisterRequest request);

//        Task<AuthResult> LoginAsync(LoginRequest request);
//        Task<AuthResult> EmailVerifyAsync(VerifyEmailRequest request);
//        Task<AuthResult> ResendVerificationCodeEndpointAsync(ResendCodeRequest request);
//        Task<AuthResult> RefreshTokenAsync(string refreshToken);
//    }
//    public class AuthenticationService : IAuthenticationService
//    {
//        private readonly UserManager<ApplicationUser> _userManager;
//        private readonly RoleManager<ApplicationRole> _roleManager;
//        private readonly SignInManager<ApplicationUser> _signInManager;
//        private readonly AppDbContext _context;
//        private readonly IConfiguration _configuration;
//        private readonly IEmailService _emailService;
//        private readonly IMailService _mailService;
//        private readonly ILoggingService _logger;

//        // Configuration constants
//        private const int MAX_LOGIN_ATTEMPTS = 5;
//        private const int LOCKOUT_DURATION_MINUTES = 15;
//        private const int VERIFICATION_CODE_LENGTH = 6;
//        private const int MAX_VERIFICATION_ATTEMPTS = 3;
//        private const int RATE_LIMIT_SECONDS = 60;
//        private const int MAX_ACTIVE_REFRESH_TOKENS_PER_DEVICE = 5;
//        private const int IP_LOGIN_MAX_ATTEMPTS = 20;
//        private const int IP_LOGIN_WINDOW_MINUTES = 15;
//        private const int IP_REGISTRATION_MAX_ATTEMPTS = 5;
//        private const int IP_REGISTRATION_WINDOW_MINUTES = 60;
//        private const int PENDING_LOGIN_RESEND_MAX = 3;

//        public AuthenticationService(
//            UserManager<ApplicationUser> userManager,
//            RoleManager<ApplicationRole> roleManager,
//            SignInManager<ApplicationUser> signInManager,
//            AppDbContext context,
//            IConfiguration configuration,
//            IEmailService emailService,
//            IMailService mailService,
//            ILoggingService loggingService)
//        {
//            _userManager = userManager;
//            _roleManager = roleManager;
//            _signInManager = signInManager;
//            _context = context;
//            _configuration = configuration;
//            _emailService = emailService;
//            _mailService = mailService;
//            _logger = loggingService;

//            ValidateConfiguration();
//        }

//        public async Task<AuthResult> RegisterAsync(RegisterRequest request)
//        {
//            var correlationId = Guid.NewGuid().ToString();

//            try
//            {
//                _logger.LogInfo("Registration attempt started", new { CorrelationId = correlationId, Email = request.Email });

//                var ipRateLimit = await CheckIpRateLimit(
//    request.IpAddress,
//    "Registration",
//    maxAttempts: 5,
//    windowMinutes: 60,
//    correlationId);

//                if (ipRateLimit != null)
//                {
//                    await LogAuditAsync(null, "Registration", request.IpAddress, null,
//                        false, "IP rate limit exceeded", correlationId);
//                    return ipRateLimit;
//                }

//                // Validate input with enhanced validation
//                var validationResult = ValidateUserRegistrationInput(request);
//                if (!validationResult.IsValid)
//                {
//                    _logger.LogWarning("Registration validation failed", new { CorrelationId = correlationId, Error = validationResult.ErrorMessage });
//                    return AuthResult.Failure(validationResult.ErrorMessage);
//                }

//                var normalizedEmail = NormalizeEmail(request.Email);
//                var sanitizedPhone = SanitizePhoneNumber(request.PhoneNumber);

//                // Check existing user with database lock to prevent race conditions
//                var existingUser = await _context.Users
//    .FromSqlRaw("SELECT * FROM AspNetUsers WITH (UPDLOCK, HOLDLOCK) WHERE Email = {0}", normalizedEmail)
//    .FirstOrDefaultAsync();
//                //var existingUser = await _context.Users
//                //    .Where(u => u.Email == normalizedEmail)
//                //    .FirstOrDefaultAsync();

//                if (existingUser != null)
//                {
//                    return await HandleExistingUserRegistration(existingUser, request, correlationId);
//                }

//                // Check phone uniqueness
//                var phoneExists = await _context.Users.AnyAsync(u => u.PhoneNumber == sanitizedPhone);
//                if (phoneExists)
//                {
//                    _logger.LogWarning("Registration failed - phone exists", new { CorrelationId = correlationId });
//                    return AuthResult.Failure("User with this phone number already exists");
//                }

//                return await CreateNewUser(request, normalizedEmail, sanitizedPhone, correlationId);
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError("Registration failed", ex, new { CorrelationId = correlationId, Email = request.Email });
//                return AuthResult.Failure("Registration failed. Please try again later.");
//            }
//        }

//        public async Task<AuthResult> LoginAsync(LoginRequest request)
//        {
//            var correlationId = Guid.NewGuid().ToString();

//            try
//            {
//                _logger.LogInfo("Login attempt started", new { CorrelationId = correlationId, Email = request.Email, IpAddress = request.IpAddress });

//                var ipRateLimit = await CheckIpRateLimit(
//    request.IpAddress,
//    "LoginAttempt",
//    maxAttempts: 20,
//    windowMinutes: 15,
//    correlationId);

//                if (ipRateLimit != null)
//                {
//                    await LogAuditAsync(null, "LoginAttempt", request.IpAddress, request.UserAgent,
//                        false, "IP rate limit exceeded", correlationId);
//                    return ipRateLimit;
//                }

//                var normalizedEmail = NormalizeEmail(request.Email);
//                var user = await _userManager.FindByEmailAsync(normalizedEmail);

//                if (user == null)
//                {
//                    // Prevent email enumeration - consistent response time
//                    await Task.Delay(Random.Shared.Next(100, 300));
//                    _logger.LogWarning("Login failed - user not found", new { CorrelationId = correlationId, Email = normalizedEmail });
//                    return AuthResult.Failure("Invalid email or password");
//                }

//                // Check if account is locked
//                var lockoutCheck = await CheckAndHandleLockout(user, request.IpAddress, correlationId);
//                if (lockoutCheck != null)
//                {
//                    return lockoutCheck; 
//                }

//                // Validate password
//                var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
//                if (!passwordValid)
//                {
//                    var delay = await CalculateLoginDelay(user.Id);
//                    if (delay > 0)
//                    {
//                        await Task.Delay(delay);
//                    }

//                    await HandleFailedLoginAttempt(user, request.IpAddress, request.UserAgent, correlationId);
//                    return AuthResult.Failure("Invalid email or password");
//                }

//                //// Reset failed attempts on successful password validation
//                //await ResetFailedLoginAttempts(user.Id);

//                // Check if account is inactive
//                if (!user.IsActive)
//                {
//                    _logger.LogWarning("Login failed - account inactive", new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure("Account is inactive. Please contact support.");
//                }

//                // Handle pending/unverified accounts
//                if (user.Status == UserStatus.Pending)
//                {
//                    return await HandlePendingAccountLogin(user, request, correlationId);
//                }

//                // Check other non-active statuses
//                if (user.Status != UserStatus.Active)
//                {
//                    _logger.LogWarning("Login failed - account status issue", new { CorrelationId = correlationId, UserId = user.Id, Status = user.Status });
//                    return AuthResult.Failure($"Account is {user.Status.ToString().ToLower()}. Please contact support.");
//                }

//                // Successful login - cleanup old refresh tokens
//                await CleanupOldRefreshTokens(user.Id, request.DeviceInfo);

//                // Update last login
//                user.LastLoginAt = DateTime.UtcNow;
//                user.UpdatedAt = DateTime.UtcNow;
//                await _userManager.UpdateAsync(user);

//                // Generate tokens
//                var accessToken = GenerateAccessToken(user);
//                var refreshToken = await GenerateRefreshTokenAsync(user.Id, request.DeviceInfo, request.IpAddress);

//                // Log successful login
//                await LogAuditAsync(user.Id, "Login", request.IpAddress, request.UserAgent, true, "Successful login", correlationId);
//                _logger.LogInfo("Login successful", new { CorrelationId = correlationId, UserId = user.Id });

//                return AuthResult.Success(accessToken, refreshToken, user);
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError("Login failed with exception", ex, new { CorrelationId = correlationId, Email = request.Email });
//                return AuthResult.Failure("Login failed. Please try again later.");
//            }
//        }

//        public async Task<AuthResult> EmailVerifyAsync(VerifyEmailRequest request)
//        {
//            var correlationId = Guid.NewGuid().ToString();

//            try
//            {
//                _logger.LogInfo("Email verification attempt started", new { CorrelationId = correlationId, Email = request.Email });

//                var normalizedEmail = NormalizeEmail(request.Email);
//                var user = await _userManager.FindByEmailAsync(normalizedEmail);

//                if (user == null)
//                {
//                    _logger.LogWarning("Email verification failed - user not found", new { CorrelationId = correlationId, Email = normalizedEmail });
//                    return AuthResult.Failure("Invalid verification request");
//                }

//                if (user.EmailVerified)
//                {
//                    _logger.LogInfo("Email verification attempted on already verified account", new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure("Email already verified. Please login.");
//                }

//                if (user.Status != UserStatus.Pending)
//                {
//                    _logger.LogInfo("Email verification attempted on non-pending account", new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure("User is not new. Please register or login.");
//                }

//                // Check verification attempts to prevent brute force
//                var tooManyAttempts = await CheckVerificationAttempts(user.Id, normalizedEmail, correlationId, request.IpAddress);
//                if (tooManyAttempts != null)
//                {
//                    return tooManyAttempts;
//                }

//                // Find the verification token
//                var verificationToken = await _context.EmailVerificationTokens
//                    .Where(t => t.Email == normalizedEmail &&
//                            t.TokenHash == request.Code &&
//                            !t.Used &&
//                            t.ExpiresAt > DateTime.UtcNow)
//                    .OrderByDescending(t => t.CreatedAt)
//                    .FirstOrDefaultAsync();

//                if (verificationToken == null)
//                {
//                    await RecordFailedVerificationAttempt(user.Id, normalizedEmail);

//                    // Check if code is expired
//                    var expiredToken = await _context.EmailVerificationTokens
//                        .Where(t => t.Email == normalizedEmail &&
//                                t.TokenHash == request.Code &&
//                                !t.Used)
//                        .FirstOrDefaultAsync();

//                    if (expiredToken != null)
//                    {
//                        _logger.LogWarning("Email verification failed - code expired", new { CorrelationId = correlationId, UserId = user.Id });
//                        return AuthResult.Failure("Verification code has expired. Please request a new one.");
//                    }

//                    _logger.LogWarning("Email verification failed - invalid code", new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure("Invalid verification code");
//                }

//                await using var transaction = await _context.Database.BeginTransactionAsync();

//                try
//                {
//                    // Mark token as used
//                    verificationToken.Used = true;
//                    verificationToken.UsedAt = DateTime.UtcNow;

//                    // Update user status
//                    user.EmailVerified = true;
//                    user.Status = UserStatus.Active;
//                    user.UpdatedAt = DateTime.UtcNow;

//                    // Clear any failed verification attempts
//                    //await ClearVerificationAttempts(user.Id, normalizedEmail);

//                    await _context.SaveChangesAsync();
//                    await transaction.CommitAsync();

//                    // Log audit
//                    await LogAuditAsync(user.Id, "EmailVerification", null, null, true, "Email verified successfully", correlationId);
//                    _logger.LogInfo("Email verification successful", new { CorrelationId = correlationId, UserId = user.Id });

//                    // Generate tokens for authenticated session
//                    var accessToken = GenerateAccessToken(user);
//                    var refreshToken = await GenerateRefreshTokenAsync(user.Id, request.DeviceInfo, request.IpAddress);

//                    return AuthResult.Success(accessToken, refreshToken, user);
//                }
//                catch (Exception ex)
//                {
//                    await transaction.RollbackAsync();
//                    _logger.LogError("Email verification transaction failed", ex, new { CorrelationId = correlationId, UserId = user.Id });
//                    throw;
//                }
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError("Email verification failed", ex, new { CorrelationId = correlationId, Email = request.Email });
//                return AuthResult.Failure("Verification failed. Please try again.");
//            }
//        }

//        public async Task<AuthResult> ResendVerificationCodeEndpointAsync(ResendCodeRequest request)
//        {
//            var correlationId = Guid.NewGuid().ToString();

//            try
//            {
//                _logger.LogInfo("Resend verification code attempt", new { CorrelationId = correlationId, Email = request.Email });

//                var normalizedEmail = NormalizeEmail(request.Email);
//                var user = await _userManager.FindByEmailAsync(normalizedEmail);

//                if (user == null)
//                {
//                    // Don't reveal that user doesn't exist
//                    await Task.Delay(Random.Shared.Next(100, 300));
//                    _logger.LogWarning("Resend code attempted for non-existent user", new { CorrelationId = correlationId, Email = normalizedEmail });
//                    return AuthResult.Failure("If an account exists with this email, a verification code has been sent.");
//                }

//                if (user.EmailVerified || user.Status != UserStatus.Pending)
//                {
//                    _logger.LogInfo("Resend code attempted for non-pending account", new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure("Email already verified. Please login.");
//                }

//                if (string.IsNullOrWhiteSpace(user.Email))
//                {
//                    _logger.LogError("User account has no email", null, new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure("Invalid account configuration. Please contact support.");
//                }

//                // Check rate limiting
//                var rateLimitCheck = await CheckResendRateLimit(user.Id, user.Email);
//                if (!rateLimitCheck.Succeeded)
//                {
//                    _logger.LogWarning("Resend code rate limited", new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure(rateLimitCheck.Message);
//                }

//                var result = await ResendVerificationCodeAsync(user.Id, user.Email, correlationId);
//                if (!result.Succeeded)
//                {
//                    return AuthResult.Failure(result.Message);
//                }

//                _logger.LogInfo("Verification code resent successfully", new { CorrelationId = correlationId, UserId = user.Id });

//                return AuthResult.PendingVerification(
//                    userId: user.Id,
//                    email: user.Email,
//                    message: "Verification code has been resent to your email."
//                );
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError("Failed to resend verification code", ex, new { CorrelationId = correlationId, Email = request.Email });
//                return AuthResult.Failure("Failed to send verification code. Please try again later.");
//            }
//        }

//        public async Task<AuthResult> RefreshTokenAsync(string refreshToken)
//        {
//            var correlationId = Guid.NewGuid().ToString();

//            try
//            {
//                _logger.LogInfo("Token refresh attempt", new { CorrelationId = correlationId });

//                var tokenHash = HashToken(refreshToken);
//                var storedToken = await _context.RefreshTokens
//                    .Include(t => t.User)
//                    .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && !t.Revoked);

//                if (storedToken == null)
//                {
//                    _logger.LogWarning("Token refresh failed - invalid token", new { CorrelationId = correlationId });
//                    return AuthResult.Failure("Invalid refresh token");
//                }

//                if (storedToken.ExpiresAt < DateTime.UtcNow)
//                {
//                    storedToken.Revoked = true;
//                    storedToken.RevokedAt = DateTime.UtcNow;
//                    storedToken.RevokedReason = "Token expired";
//                    await _context.SaveChangesAsync();

//                    _logger.LogWarning("Token refresh failed - token expired", new { CorrelationId = correlationId, UserId = storedToken.UserId });
//                    return AuthResult.Failure("Refresh token expired. Please login again.");
//                }

//                var user = storedToken.User;
//                if (!user.IsActive || user.Status != UserStatus.Active)
//                {
//                    _logger.LogWarning("Token refresh failed - user inactive", new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure("Account is not active. Please contact support.");
//                }

//                // Generate new tokens
//                var accessToken = GenerateAccessToken(user);
//                var newRefreshToken = await GenerateRefreshTokenAsync(user.Id, storedToken.DeviceInfo, storedToken.IpAddress);

//                // Revoke old refresh token
//                storedToken.Revoked = true;
//                storedToken.RevokedAt = DateTime.UtcNow;
//                storedToken.RevokedReason = "Token refreshed";
//                await _context.SaveChangesAsync();

//                _logger.LogInfo("Token refresh successful", new { CorrelationId = correlationId, UserId = user.Id });

//                return AuthResult.Success(accessToken, newRefreshToken, user);
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError("Token refresh failed", ex, new { CorrelationId = correlationId });
//                return AuthResult.Failure("Token refresh failed. Please login again.");
//            }
//        }

//        // PRIVATE HELPER METHODS

//        private async Task<AuthResult> HandleExistingUserRegistration(ApplicationUser existingUser, RegisterRequest request, string correlationId)
//        {
//            if (existingUser.EmailVerified)
//            {
//                _logger.LogWarning("Registration attempted for verified account", new { CorrelationId = correlationId, UserId = existingUser.Id });
//                return AuthResult.Failure("An account with this email already exists. Please login.");
//            }

//            if (string.IsNullOrWhiteSpace(existingUser.Email))
//            {
//                _logger.LogError("Existing user has no email", null, new { CorrelationId = correlationId, UserId = existingUser.Id });
//                return AuthResult.Failure("Invalid account configuration. Please contact support.");
//            }

//            await using var transaction = await _context.Database.BeginTransactionAsync();

//            try
//            {


//                // Update user information
//                existingUser.FirstName = SanitizeInput(request.FirstName, 50);
//                existingUser.LastName = SanitizeInput(request.LastName, 50);
//                existingUser.PhoneNumber = SanitizePhoneNumber(request.PhoneNumber);
//                existingUser.UserType = request.UserType;
//                existingUser.UpdatedAt = DateTime.UtcNow;

//                // Update password
//                var removePasswordResult = await _userManager.RemovePasswordAsync(existingUser);
//                if (removePasswordResult.Succeeded)
//                {
//                    var addPasswordResult = await _userManager.AddPasswordAsync(existingUser, request.Password);
//                    if (!addPasswordResult.Succeeded)
//                    {
//                        _logger.LogWarning("Password update failed during registration update", new { CorrelationId = correlationId, UserId = existingUser.Id });
//                        return AuthResult.Failure("Failed to update password");
//                    }
//                }

//                // Update role if needed
//                await UpdateUserRole(existingUser, request.UserType);

//                // Update type-specific data
//                await UpdateUserTypeSpecificData(existingUser, request);

//                await _context.SaveChangesAsync();

//                // Resend verification code
//                var resendResult = await ResendVerificationCodeAsync(existingUser.Id, existingUser.Email, correlationId);
//                if (!resendResult.Succeeded)
//                {
//                    await transaction.RollbackAsync();
//                    return AuthResult.Failure("Failed to send verification code. Please try again.");
//                }

//                await transaction.CommitAsync();

//                await LogAuditAsync(existingUser.Id, "RegistrationUpdate", null, null, true,
//                    $"User updated registration details as {request.UserType} - verification code resent", correlationId);

//                _logger.LogInfo("Existing user registration updated", new { CorrelationId = correlationId, UserId = existingUser.Id });

//                return AuthResult.PendingVerification(
//                    userId: existingUser.Id,
//                    email: existingUser.Email,
//                    message: "Your registration details have been updated. A verification code has been sent to your email."
//                );
//            }
//            catch (Exception ex)
//            {
//                await transaction.RollbackAsync();
//                _logger.LogError("Transaction failed during registration update", ex, new { CorrelationId = correlationId, UserId = existingUser.Id });
//                throw;
//            }
//        }

//        private async Task<AuthResult> CreateNewUser(RegisterRequest request, string normalizedEmail, string sanitizedPhone, string correlationId)
//        {
//            await using var transaction = await _context.Database.BeginTransactionAsync();

//            try
//            {
//                var user = new ApplicationUser
//                {
//                    UserName = normalizedEmail,
//                    Email = normalizedEmail,
//                    FirstName = request.FirstName,
//                    LastName = request.LastName,
//                    PhoneNumber = sanitizedPhone,
//                    UserType = request.UserType,
//                    Status = UserStatus.Pending,
//                    EmailVerified = false,
//                    CreatedAt = DateTime.UtcNow,
//                    UpdatedAt = DateTime.UtcNow
//                };

//                var createResult = await _userManager.CreateAsync(user, request.Password);
//                if (!createResult.Succeeded)
//                {
//                    var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
//                    _logger.LogWarning("User creation failed", new { CorrelationId = correlationId, Email = normalizedEmail, Errors = errors });
//                    return AuthResult.Failure(errors);
//                }

//                // Assign role
//                var roleName = request.UserType.ToString();
//                if (!await _roleManager.RoleExistsAsync(roleName))
//                {
//                    _logger.LogError("Role does not exist", null, new { CorrelationId = correlationId, Role = roleName });
//                    return AuthResult.Failure("Invalid role configuration. Please contact support.");
//                }

//                var roleResult = await _userManager.AddToRoleAsync(user, roleName);
//                if (!roleResult.Succeeded)
//                {
//                    _logger.LogError("Role assignment failed", null, new { CorrelationId = correlationId, UserId = user.Id, Role = roleName });
//                    return AuthResult.Failure("Failed to assign user role");
//                }

//                // Handle user type-specific data
//                await CreateUserTypeSpecificData(user, request);

//                await _context.SaveChangesAsync();

//                // Generate and send verification code
//                var verificationResult = await GenerateAndSendVerificationCodeAsync(user.Id, user.Email, correlationId);
//                if (!verificationResult.Succeeded)
//                {
//                    await transaction.CommitAsync();
//                    _logger.LogWarning("Account created but email sending failed", new { CorrelationId = correlationId, UserId = user.Id });
//                    return AuthResult.Failure("Account created but failed to send verification email. Please request a new code.");
//                }

//                await transaction.CommitAsync();

//                await LogAuditAsync(user.Id, "Registration", null, null, true,
//                    $"User registered as {request.UserType} - pending email verification", correlationId);

//                _logger.LogInfo("User registration successful", new { CorrelationId = correlationId, UserId = user.Id });

//                return AuthResult.PendingVerification(
//                    userId: user.Id,
//                    email: user.Email,
//                    message: "Registration successful. Please check your email for the verification code."
//                );
//            }
//            catch (Exception ex)
//            {
//                await transaction.RollbackAsync();
//                _logger.LogError("Transaction failed during user creation", ex, new { CorrelationId = correlationId, Email = normalizedEmail });
//                throw;
//            }
//        }

//        private async Task<AuthResult?> CheckAndHandleLockout(
//    ApplicationUser user,
//    string? ipAddress,
//    string correlationId)
//        {
//            var failedAttempts = await _context.AuditLogs
//                .Where(l => l.UserId == user.Id &&
//                       l.Action == "LoginAttempt" &&
//                       !l.Success &&
//                       l.CreatedAt > DateTime.UtcNow.AddMinutes(-LOCKOUT_DURATION_MINUTES))
//                .CountAsync();

//            if (failedAttempts >= MAX_LOGIN_ATTEMPTS)
//            {
//                var oldestFailedAttempt = await _context.AuditLogs
//                    .Where(l => l.UserId == user.Id &&
//                           l.Action == "LoginAttempt" &&
//                           !l.Success)
//                    .OrderByDescending(l => l.CreatedAt)
//                    .Skip(MAX_LOGIN_ATTEMPTS - 1)
//                    .FirstOrDefaultAsync();

//                if (oldestFailedAttempt != null)
//                {
//                    var lockoutTimeRemaining = LOCKOUT_DURATION_MINUTES -
//                        (int)(DateTime.UtcNow - oldestFailedAttempt.CreatedAt).TotalMinutes;

//                    if (lockoutTimeRemaining > 0)
//                    {
//                        _logger.LogWarning("Login attempt on locked account",
//                            new
//                            {
//                                CorrelationId = correlationId,
//                                UserId = user.Id,
//                                RemainingMinutes = lockoutTimeRemaining
//                            });

//                        await LogAuditAsync(user.Id, "LoginAttempt", ipAddress, null, false,
//                            $"Account locked - {lockoutTimeRemaining} minutes remaining", correlationId);

//                        // **ADD: Add delay to prevent timing attacks**
//                        await Task.Delay(Random.Shared.Next(1000, 2000));

//                        return AuthResult.Failure(
//                            $"Account is temporarily locked due to multiple failed login attempts. " +
//                            $"Please try again in {lockoutTimeRemaining} minutes.");
//                    }
//                }
//            }

//            return null;
//        }
//        private async Task HandleFailedLoginAttempt(ApplicationUser user, string? ipAddress, string? userAgent, string correlationId)
//        {
//            await LogAuditAsync(user.Id, "LoginAttempt", ipAddress, userAgent, false, "Invalid password", correlationId);

//            var recentFailedAttempts = await _context.AuditLogs
//                .Where(l => l.UserId == user.Id &&
//                       l.Action == "LoginAttempt" &&
//                       !l.Success &&
//                       l.CreatedAt > DateTime.UtcNow.AddMinutes(-LOCKOUT_DURATION_MINUTES))
//                .CountAsync();

//            _logger.LogWarning("Failed login attempt", new
//            {
//                CorrelationId = correlationId,
//                UserId = user.Id,
//                FailedAttempts = recentFailedAttempts + 1,
//                RemainingAttempts = MAX_LOGIN_ATTEMPTS - (recentFailedAttempts + 1)
//            });
//        }

//        //private async Task ResetFailedLoginAttempts(string userId)
//        //{
//        //    // Optional: Could delete old failed attempts or just rely on time-based check
//        //    // For now, we just log the successful validation
//        //    _logger.LogInfo("Failed login attempts reset", new { UserId = userId });
//        //}

//        private async Task<AuthResult> HandlePendingAccountLogin(
//            ApplicationUser user,
//            LoginRequest request,
//            string correlationId)
//        {
//            if (string.IsNullOrWhiteSpace(user.Email))
//            {
//                _logger.LogError("Pending account has no email", null,
//                    new { CorrelationId = correlationId, UserId = user.Id });
//                return AuthResult.Failure("Invalid account configuration. Please contact support.");
//            }

//            // **NEW: Check rate limiting for pending account login attempts**
//            var recentPendingLoginAttempts = await _context.AuditLogs
//                .Where(l => l.UserId == user.Id &&
//                       l.Action == "LoginAttempt" &&
//                       l.Details != null && l.Details.Contains("pending verification") &&
//                       l.CreatedAt > DateTime.UtcNow.AddMinutes(-LOCKOUT_DURATION_MINUTES))
//                .CountAsync();

//            if (recentPendingLoginAttempts >= 3) // Max 3 resend attempts per lockout window
//            {
//                var oldestAttempt = await _context.AuditLogs
//                    .Where(l => l.UserId == user.Id &&
//                           l.Action == "LoginAttempt" &&
//                           l.Details != null && l.Details.Contains("pending verification"))
//                    .OrderByDescending(l => l.CreatedAt)
//                    .Skip(2)
//                    .FirstOrDefaultAsync();

//                if (oldestAttempt != null)
//                {
//                    var lockoutRemaining = LOCKOUT_DURATION_MINUTES -
//                        (int)(DateTime.UtcNow - oldestAttempt.CreatedAt).TotalMinutes;

//                    if (lockoutRemaining > 0)
//                    {
//                        _logger.LogWarning("Pending account login rate limited",
//                            new { CorrelationId = correlationId, UserId = user.Id });

//                        await LogAuditAsync(user.Id, "LoginAttempt", request.IpAddress,
//                            request.UserAgent, false,
//                            $"Rate limited - {lockoutRemaining} minutes remaining",
//                            correlationId);

//                        return AuthResult.Failure(
//                            $"Too many verification attempts. Please try again in {lockoutRemaining} minutes.");
//                    }
//                }
//            }

//            // **NEW: Also check per-user resend rate limit**
//            var rateLimitCheck = await CheckResendRateLimit(user.Id, user.Email);
//            if (!rateLimitCheck.Succeeded)
//            {
//                await LogAuditAsync(user.Id, "LoginAttempt", request.IpAddress,
//                    request.UserAgent, false, rateLimitCheck.Message, correlationId);
//                return AuthResult.Failure(rateLimitCheck.Message);
//            }

//            var verificationResult = await ResendVerificationCodeAsync(user.Id, user.Email, correlationId);
//            if (!verificationResult.Succeeded)
//            {
//                _logger.LogWarning("Failed to resend verification during login",
//                    new { CorrelationId = correlationId, UserId = user.Id });
//                return AuthResult.Failure(
//                    "Account pending verification, but failed to send verification code. Please try again.");
//            }

//            await LogAuditAsync(user.Id, "LoginAttempt", request.IpAddress, request.UserAgent, false,
//                "Login attempted - account pending verification, code resent", correlationId);

//            _logger.LogInfo("Pending account login handled",
//                new { CorrelationId = correlationId, UserId = user.Id });

//            return AuthResult.PendingVerification(
//                userId: user.Id,
//                email: user.Email,
//                message: "Your account is pending email verification. A new verification code has been sent to your email."
//            );
//        }
//        private void ValidateConfiguration()
//        {
//            var errors = new List<string>();

//            // Validate JWT settings
//            var jwtKey = _configuration["JwtSettings:SecretKey"];
//            if (string.IsNullOrWhiteSpace(jwtKey))
//                errors.Add("JwtSettings:SecretKey is missing");
//            else if (jwtKey.Length < 32)
//                errors.Add("JwtSettings:SecretKey must be at least 32 characters long");

//            if (string.IsNullOrWhiteSpace(_configuration["JwtSettings:Issuer"]))
//                errors.Add("JwtSettings:Issuer is missing");

//            if (string.IsNullOrWhiteSpace(_configuration["JwtSettings:Audience"]))
//                errors.Add("JwtSettings:Audience is missing");

//            var expiryMinutes = _configuration["JwtSettings:ExpiryMinutes"];
//            if (string.IsNullOrWhiteSpace(expiryMinutes) || !int.TryParse(expiryMinutes, out var expiry) || expiry <= 0)
//                errors.Add("JwtSettings:ExpiryMinutes must be a positive integer");

//            var refreshTokenDays = _configuration["JwtSettings:RefreshTokenExpiryDays"];
//            if (!string.IsNullOrWhiteSpace(refreshTokenDays) && (!int.TryParse(refreshTokenDays, out var days) || days <= 0))
//                errors.Add("JwtSettings:RefreshTokenExpiryDays must be a positive integer");

//            if (errors.Any())
//            {
//                var errorMessage = $"Configuration validation failed: {string.Join("; ", errors)}";
//                _logger.LogError(errorMessage, null, new { Errors = errors });
//                throw new InvalidOperationException(errorMessage);
//            }

//            _logger.LogInfo("Configuration validation successful", new { });
//        }

//        // ============================================================================
//        // VERIFICATION & CODE MANAGEMENT
//        // ============================================================================

//        private async Task<AuthResult?> CheckVerificationAttempts(
//    string userId,
//    string email,
//    string correlationId,
//    string? ipAddress)
//        {
//            var windowStart = DateTime.UtcNow.AddMinutes(-LOCKOUT_DURATION_MINUTES);

//            var failedAttemptsQuery = _context.AuditLogs
//                .Where(l =>
//                    l.UserId == userId &&
//                    l.Action == "EmailVerification" &&
//                    !l.Success &&
//                    l.CreatedAt >= windowStart);

//            var failedAttempts = await failedAttemptsQuery.CountAsync();

//            if (failedAttempts < MAX_VERIFICATION_ATTEMPTS)
//                return null;


//            var earliestFailedAttempt = await failedAttemptsQuery
//                .OrderBy(l => l.CreatedAt)
//                .FirstAsync();

//            var lockoutEndsAt = earliestFailedAttempt.CreatedAt
//                .AddMinutes(LOCKOUT_DURATION_MINUTES);

//            var remainingMinutes = (int)Math.Ceiling(
//                (lockoutEndsAt - DateTime.UtcNow).TotalMinutes);

//            if (remainingMinutes > 0)
//            {
//                _logger.LogWarning(
//                    "Email verification attempt on locked account",
//                    new
//                    {
//                        CorrelationId = correlationId,
//                        UserId = userId,
//                        RemainingMinutes = remainingMinutes
//                    });


//                return AuthResult.Failure(
//                    $"Too many verification attempts. Please try again in {remainingMinutes} minutes.");
//            }

//            return null;
//        }


//        private async Task RecordFailedVerificationAttempt(string userId, string email)
//        {
//            await LogAuditAsync(userId, "EmailVerification", null, null, false, "Invalid verification code");
//        }

//        //private async Task ClearVerificationAttempts(string userId, string email)
//        //{
//        //    // Optional: Clean up failed verification attempt logs
//        //    // For now, we rely on time-based filtering
//        //    _logger.LogInfo("Verification attempts cleared", new { UserId = userId });
//        //}

//        private async Task<int> CalculateLoginDelay(string userId)
//        {
//            var recentFailures = await _context.AuditLogs
//                .Where(l => l.UserId == userId &&
//                       l.Action == "LoginAttempt" &&
//                       !l.Success &&
//                       l.CreatedAt > DateTime.UtcNow.AddMinutes(-5))
//                .CountAsync();

//            // Exponential backoff: 0, 1, 2, 4, 8 seconds
//            return recentFailures > 0 ? (int)Math.Pow(2, Math.Min(recentFailures - 1, 3)) * 1000 : 0;
//        }

//        private async Task<AuthResult?> CheckIpRateLimit(
//    string? ipAddress,
//    string action,
//    int maxAttempts,
//    int windowMinutes,
//    string correlationId)
//        {
//            if (string.IsNullOrWhiteSpace(ipAddress))
//                return null;

//            var windowStart = DateTime.UtcNow.AddMinutes(-windowMinutes);

//            var ipAttempts = await _context.AuditLogs
//                .Where(l => l.IpAddress == ipAddress &&
//                       l.Action == action &&
//                       l.CreatedAt >= windowStart)
//                .CountAsync();

//            if (ipAttempts >= maxAttempts)
//            {
//                _logger.LogWarning($"IP rate limit exceeded for {action}",
//                    new { CorrelationId = correlationId, IpAddress = ipAddress, Attempts = ipAttempts });

//                return AuthResult.Failure(
//                    "Too many requests from this IP address. Please try again later.");
//            }

//            return null;
//        }

//        private async Task<OperationResult> CheckResendRateLimit(string userId, string email)
//        {
//            var recentToken = await _context.EmailVerificationTokens
//                .Where(t => t.UserId == userId && !t.Used)
//                .OrderByDescending(t => t.CreatedAt)
//                .FirstOrDefaultAsync();

//            if (recentToken != null && recentToken.CreatedAt.AddSeconds(RATE_LIMIT_SECONDS) > DateTime.UtcNow)
//            {
//                var waitTime = (int)(RATE_LIMIT_SECONDS - (DateTime.UtcNow - recentToken.CreatedAt).TotalSeconds);
//                _logger.LogWarning("Resend verification code rate limited", new { UserId = userId, WaitSeconds = waitTime });
//                //return OperationResult.Failure($"Please wait {waitTime} seconds before requesting a new code");
//                return OperationResult.Failure($"Please wait {waitTime} seconds before retrying");
//            }

//            return OperationResult.Success();
//        }

//        private async Task<OperationResult> GenerateAndSendVerificationCodeAsync(string userId, string email, string? correlationId = null)
//        {
//            try
//            {
//                // Generate cryptographically secure 6-digit code
//                var code = GenerateSecureVerificationCode();
//                var expiryMinutes = 15;
//                var expiryTime = DateTime.UtcNow.AddMinutes(expiryMinutes);

//                // Invalidate any previous unused codes for this user
//                var existingTokens = await _context.EmailVerificationTokens
//                    .Where(t => t.Email == email && !t.Used)
//                    .ToListAsync();

//                foreach (var token in existingTokens)
//                {
//                    token.Used = true;
//                    token.UsedAt = DateTime.UtcNow;
//                }

//                // Store verification code
//                var verificationToken = new EmailVerificationToken
//                {
//                    UserId = userId,
//                    Email = email,
//                    TokenHash = code,
//                    ExpiresAt = expiryTime,
//                    Used = false,
//                    CreatedAt = DateTime.UtcNow
//                };

//                _context.EmailVerificationTokens.Add(verificationToken);
//                await _context.SaveChangesAsync();

//                // Send email with verification code
//                await _emailService.SendEmailVerificationAsync(email, code);
//    //            await _mailService.SendEmailAsync(email, "Verify your email",
//    //$"Use this code to verify: {code}");

//                _logger.LogInfo("Verification code generated and sent", new
//                {
//                    CorrelationId = correlationId,
//                    UserId = userId,
//                    ExpiryMinutes = expiryMinutes
//                });

//                return OperationResult.Success();
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError("Failed to generate and send verification code", ex, new
//                {
//                    CorrelationId = correlationId,
//                    UserId = userId
//                });
//                return OperationResult.Failure("Failed to send verification code");
//            }
//        }

//        private async Task<OperationResult> ResendVerificationCodeAsync(string userId, string email, string? correlationId = null)
//        {
//            try
//            {
//                // Rate limiting is checked by the caller
//                var result = await GenerateAndSendVerificationCodeAsync(userId, email, correlationId);

//                if (result.Succeeded)
//                {
//                    await LogAuditAsync(userId, "VerificationCodeResent", null, null, true, "Verification code resent", correlationId);
//                }

//                return result;
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError("Failed to resend verification code", ex, new
//                {
//                    CorrelationId = correlationId,
//                    UserId = userId
//                });
//                return OperationResult.Failure("Failed to send verification code");
//            }
//        }

//        private string GenerateSecureVerificationCode()
//        {
//            using var rng = RandomNumberGenerator.Create();
//            var bytes = new byte[4];
//            rng.GetBytes(bytes);
//            var number = BitConverter.ToUInt32(bytes, 0);
//            return (number % 1000000).ToString("D6");
//        }

//        // ============================================================================
//        // TOKEN GENERATION & MANAGEMENT
//        // ============================================================================

//        private async Task CleanupOldRefreshTokens(string userId, string? deviceInfo)
//        {
//            if (string.IsNullOrWhiteSpace(deviceInfo))
//                return;

//            var now = DateTime.UtcNow;

//            var tokensToRevoke = await _context.RefreshTokens
//                .Where(t =>
//                    t.UserId == userId &&
//                    t.DeviceInfo == deviceInfo &&
//                    !t.Revoked &&
//                    t.ExpiresAt > now)
//                .ToListAsync();

//            if (tokensToRevoke.Count == 0)
//                return;

//            foreach (var token in tokensToRevoke)
//            {
//                token.Revoked = true;
//                token.RevokedAt = now;
//                token.RevokedReason = "Superseded by new login";
//            }

//            await _context.SaveChangesAsync();
//        }


//        private string GenerateAccessToken(ApplicationUser user)
//        {
//            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
//            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//            var claims = new List<Claim>
//            {
//                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
//                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
//                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
//                new Claim(ClaimTypes.NameIdentifier, user.Id),
//                new Claim(ClaimTypes.Email, user.Email!),
//                new Claim("userType", user.UserType.ToString()),
//                new Claim("fullName", user.FullName),
//                new Claim("emailVerified", user.EmailVerified.ToString()),
//                new Claim("status", user.Status.ToString())
//            };

//            var token = new JwtSecurityToken(
//                issuer: _configuration["Jwt:Issuer"],
//                audience: _configuration["Jwt:Audience"],
//                claims: claims,
//                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryMinutes"])),
//                signingCredentials: credentials
//            );

//            return new JwtSecurityTokenHandler().WriteToken(token);
//        }

//        private async Task<string> GenerateRefreshTokenAsync(string userId, string? deviceInfo, string? ipAddress)
//        {
//            var token = GenerateSecureToken();
//            var tokenHash = HashToken(token);

//            var refreshToken = new RefreshToken
//            {
//                UserId = userId,
//                TokenHash = tokenHash,
//                DeviceInfo = SanitizeInput(deviceInfo, 200),
//                IpAddress = ipAddress,
//                ExpiresAt = DateTime.UtcNow.AddDays(Convert.ToDouble(_configuration["JwtSettings:RefreshTokenExpiryDays"] ?? "30")),
//                CreatedAt = DateTime.UtcNow
//            };

//            _context.RefreshTokens.Add(refreshToken);
//            await _context.SaveChangesAsync();

//            return token;
//        }

//        private string GenerateSecureToken()
//        {
//            var randomBytes = new byte[32];
//            using (var rng = RandomNumberGenerator.Create())
//            {
//                rng.GetBytes(randomBytes);
//            }
//            return Convert.ToBase64String(randomBytes);
//        }

//        private string HashToken(string token)
//        {
//            using var sha256 = SHA256.Create();
//            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
//            return Convert.ToBase64String(hashBytes);
//        }

//        // ============================================================================
//        // USER TYPE-SPECIFIC DATA MANAGEMENT
//        // ============================================================================

//        private async Task UpdateUserRole(ApplicationUser user, UserType newUserType)
//        {
//            var currentRoles = await _userManager.GetRolesAsync(user);
//            var newRoleName = newUserType.ToString();

//            if (!await _roleManager.RoleExistsAsync(newRoleName))
//            {
//                throw new InvalidOperationException($"Role {newRoleName} does not exist");
//            }

//            if (!currentRoles.Contains(newRoleName))
//            {
//                if (currentRoles.Any())
//                {
//                    await _userManager.RemoveFromRolesAsync(user, currentRoles);
//                }
//                var roleResult = await _userManager.AddToRoleAsync(user, newRoleName);
//                if (!roleResult.Succeeded)
//                {
//                    throw new InvalidOperationException("Failed to assign user role");
//                }
//            }
//        }

//        private async Task UpdateUserTypeSpecificData(ApplicationUser user, RegisterRequest request)
//        {
//            if (request.UserType == UserType.User)
//            {
//                // Remove old artisan profile and services if switching from Artisan to User
//                var oldArtisanProfile = await _context.ArtisanProfiles
//                    .FirstOrDefaultAsync(ap => ap.UserId == user.Id);

//                if (oldArtisanProfile != null)
//                {
//                    var oldServices = await _context.Services
//                        .Where(s => s.ArtisanId == oldArtisanProfile.Id)
//                        .ToListAsync();

//                    _context.Services.RemoveRange(oldServices);
//                    _context.ArtisanProfiles.Remove(oldArtisanProfile);

//                    _logger.LogInfo("Removed artisan profile during type switch", new { UserId = user.Id });
//                }

//                // Remove old preferences
//                var oldPreferences = await _context.ServicePreferences
//                    .Where(sp => sp.UserId == user.Id)
//                    .ToListAsync();
//                _context.ServicePreferences.RemoveRange(oldPreferences);

//                // Add new preferences
//                if (request.ServicePreferences?.Any() == true)
//                {
//                    var newPreferences = request.ServicePreferences.Select(sp => new ServicePreference
//                    {
//                        UserId = user.Id,
//                        ServiceCategory = sp,
//                        CreatedAt = DateTime.UtcNow
//                    }).ToList();
//                    _context.ServicePreferences.AddRange(newPreferences);
//                }
//            }
//            else if (request.UserType == UserType.Artisan)
//            {
//                // Remove old service preferences if switching from User to Artisan
//                var oldPreferences = await _context.ServicePreferences
//                    .Where(sp => sp.UserId == user.Id)
//                    .ToListAsync();
//                _context.ServicePreferences.RemoveRange(oldPreferences);

//                // Update or create artisan profile
//                var existingProfile = await _context.ArtisanProfiles
//                    .FirstOrDefaultAsync(ap => ap.UserId == user.Id);

//                if (existingProfile != null)
//                {
//                    existingProfile.BusinessName = SanitizeInput(request.BusinessName, 100);
//                    existingProfile.UpdatedAt = DateTime.UtcNow;

//                    // Remove old services
//                    var oldServices = await _context.Services
//                        .Where(s => s.ArtisanId == existingProfile.Id)
//                        .ToListAsync();
//                    _context.Services.RemoveRange(oldServices);
//                }
//                else
//                {
//                    existingProfile = new ArtisanProfile
//                    {
//                        UserId = user.Id,
//                        BusinessName = SanitizeInput(request.BusinessName, 100),
//                        CreatedAt = DateTime.UtcNow,
//                        UpdatedAt = DateTime.UtcNow
//                    };
//                    _context.ArtisanProfiles.Add(existingProfile);
//                    await _context.SaveChangesAsync(); // Save to get the profile ID
//                }

//                // Add new service
//                if (request.Service != null)
//                {




//                        var service = new Service
//                        {
//                            ArtisanId = existingProfile.Id,
//                            Name = SanitizeInput(request.Service.Name, 100),
//                            Category = request.Service.Category,
//                            PricingModel = request.Service.PricingModel,
//                            MinPrice = request.Service.MinPrice,
//                            MaxPrice = request.Service.MaxPrice,
//                            Availability = request.Service.Availability,
//                            Notes = SanitizeInput(request.Service.Notes, 500),
//                            CreatedAt = DateTime.UtcNow,
//                            UpdatedAt = DateTime.UtcNow
//                        };
//                        _context.Services.Add(service);


//                }
//            }
//        }

//        private async Task CreateUserTypeSpecificData(ApplicationUser user, RegisterRequest request)
//        {
//            if (request.UserType == UserType.User)
//            {
//                // Store user service preferences
//                if (request.ServicePreferences?.Any() == true)
//                {
//                    var userPreferences = request.ServicePreferences.Select(sp => new ServicePreference
//                    {
//                        UserId = user.Id,
//                        ServiceCategory = sp,
//                        CreatedAt = DateTime.UtcNow
//                    }).ToList();

//                    _context.ServicePreferences.AddRange(userPreferences);
//                }
//            }
//            else if (request.UserType == UserType.Artisan)
//            {
//                // Create artisan profile
//                var artisanProfile = new ArtisanProfile
//                {
//                    UserId = user.Id,
//                    BusinessName = SanitizeInput(request.BusinessName, 100),
//                    CreatedAt = DateTime.UtcNow,
//                    UpdatedAt = DateTime.UtcNow
//                };
//                _context.ArtisanProfiles.Add(artisanProfile);
//                await _context.SaveChangesAsync(); // Save to get profile ID

//                // Add artisan's first service
//                if (request.Service != null)
//                {

//                        var service = new Service
//                        {
//                            ArtisanId = artisanProfile.Id,
//                            Name = SanitizeInput(request.Service.Name, 100),
//                            Category = request.Service.Category,
//                            PricingModel = request.Service.PricingModel,
//                            MinPrice = request.Service.MinPrice,
//                            MaxPrice = request.Service.MaxPrice,
//                            Availability = request.Service.Availability,
//                            Notes = SanitizeInput(request.Service.Notes, 500),
//                            CreatedAt = DateTime.UtcNow,
//                            UpdatedAt = DateTime.UtcNow
//                        };
//                        _context.Services.Add(service);


//                }
//            }
//        }

//        // ============================================================================
//        // INPUT VALIDATION & SANITIZATION
//        // ============================================================================

//        private async Task<bool> DetectSuspiciousActivity(
//    string? ipAddress,
//    string? userAgent,
//    string correlationId)
//        {
//            if (string.IsNullOrWhiteSpace(ipAddress))
//                return false;

//            var windowStart = DateTime.UtcNow.AddMinutes(-30);

//            // Check for attempts against multiple accounts from same IP
//            var distinctUsers = await _context.AuditLogs
//                .Where(l => l.IpAddress == ipAddress &&
//                       l.Action == "LoginAttempt" &&
//                       l.CreatedAt >= windowStart)
//                .Select(l => l.UserId)
//                .Distinct()
//                .CountAsync();

//            if (distinctUsers > 10) // More than 10 different accounts in 30 minutes
//            {
//                _logger.LogWarning("Suspicious activity detected - account enumeration attempt",
//                    new
//                    {
//                        CorrelationId = correlationId,
//                        IpAddress = ipAddress,
//                        DistinctAccounts = distinctUsers
//                    });
//                return true;
//            }

//            return false;
//        }

//        private ValidationResult ValidateUserRegistrationInput(RegisterRequest request)
//        {
//            // Email validation
//            if (string.IsNullOrWhiteSpace(request.Email))
//                return new ValidationResult(false, "Email address is required");

//            if (!new EmailAddressAttribute().IsValid(request.Email))
//                return new ValidationResult(false, "Please provide a valid email address");

//            if (request.Email.Length > 254) // RFC 5321
//                return new ValidationResult(false, "Email address is too long");

//            // Password validation
//            if (string.IsNullOrWhiteSpace(request.Password))
//                return new ValidationResult(false, "Password is required");

//            var passwordValidation = ValidatePassword(request.Password);
//            if (!passwordValidation.IsValid)
//                return passwordValidation;

//            // Name validation
//            if (string.IsNullOrWhiteSpace(request.FirstName))
//                return new ValidationResult(false, "First name is required");

//            if (request.FirstName.Length > 50)
//                return new ValidationResult(false, "First name is too long (maximum 50 characters)");

//            if (!IsValidName(request.FirstName))
//                return new ValidationResult(false, "First name contains invalid characters");

//            if (string.IsNullOrWhiteSpace(request.LastName))
//                return new ValidationResult(false, "Last name is required");

//            if (request.LastName.Length > 50)
//                return new ValidationResult(false, "Last name is too long (maximum 50 characters)");

//            if (!IsValidName(request.LastName))
//                return new ValidationResult(false, "Last name contains invalid characters");

//            // Phone validation
//            if (string.IsNullOrWhiteSpace(request.PhoneNumber))
//                return new ValidationResult(false, "Phone number is required");

//            if (!IsValidPhoneNumber(request.PhoneNumber))
//                return new ValidationResult(false, "Please provide a valid phone number");

//            // UserType validation
//            if (!Enum.IsDefined(typeof(UserType), request.UserType))
//                return new ValidationResult(false, "Invalid user type");

//            // Artisan-specific validation
//            if (request.UserType == UserType.Artisan)
//            {
//                if (string.IsNullOrWhiteSpace(request.BusinessName))
//                    return new ValidationResult(false, "Business name is required for artisan registration");

//                if (request.BusinessName.Length > 100)
//                    return new ValidationResult(false, "Business name is too long (maximum 100 characters)");

//                if (request.Service == null)
//                    return new ValidationResult(false, "At least one service is required for artisan registration");

//                // Service validation
//                if (string.IsNullOrWhiteSpace(request.Service.Name))
//                    return new ValidationResult(false, "Service name is required");

//                if (request.Service.Name.Length > 100)
//                    return new ValidationResult(false, "Service name is too long (maximum 100 characters)");

//                if (string.IsNullOrWhiteSpace(request.Service.Category))
//                    return new ValidationResult(false, "Service category is required");

//                if (!Enum.IsDefined(typeof(PricingModel), request.Service.PricingModel))
//                    return new ValidationResult(false, "Valid pricing model is required");

//                if (request.Service.MinPrice < 0)
//                    return new ValidationResult(false, "Minimum price cannot be negative");

//                if (request.Service.MaxPrice.HasValue && request.Service.MaxPrice < request.Service.MinPrice)
//                    return new ValidationResult(false, "Maximum price cannot be less than minimum price");

//                if (!string.IsNullOrWhiteSpace(request.Service.Notes) && request.Service.Notes.Length > 500)
//                    return new ValidationResult(false, "Service notes are too long (maximum 500 characters)");
//            }

//            return new ValidationResult(true);
//        }

//        private ValidationResult ValidatePassword(string password)
//        {
//            if (password.Length < 8)
//                return new ValidationResult(false, "Password must be at least 8 characters long");

//            if (password.Length > 128)
//                return new ValidationResult(false, "Password is too long (maximum 128 characters)");

//            var hasUpper = password.Any(char.IsUpper);
//            var hasLower = password.Any(char.IsLower);
//            var hasDigit = password.Any(char.IsDigit);
//            var hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));

//            var strengthScore = 0;
//            if (hasUpper) strengthScore++;
//            if (hasLower) strengthScore++;
//            if (hasDigit) strengthScore++;
//            if (hasSpecial) strengthScore++;

//            if (strengthScore < 3)
//                return new ValidationResult(false, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters");

//            // Check for common passwords (simplified - in production use a proper list)
//            var commonPasswords = new[] { "password", "12345678", "password123", "qwerty123" };
//            if (commonPasswords.Any(cp => password.ToLower().Contains(cp)))
//                return new ValidationResult(false, "Password is too common. Please choose a stronger password");

//            return new ValidationResult(true);
//        }

//        private bool IsValidName(string name)
//        {
//            // Allow letters, spaces, hyphens, apostrophes
//            return Regex.IsMatch(name, @"^[a-zA-Z\s\-']+$");
//        }

//        private bool IsValidPhoneNumber(string phoneNumber)
//        {
//            // Remove common formatting characters
//            var cleaned = Regex.Replace(phoneNumber, @"[\s\-\(\)\+]", "");

//            // Check if it's all digits and reasonable length
//            return Regex.IsMatch(cleaned, @"^\d{10,15}$");
//        }

//        private string NormalizeEmail(string email)
//        {
//            if (string.IsNullOrWhiteSpace(email))
//                return email;

//            var trimmed = email.Trim().ToLowerInvariant();

//            // Handle Gmail-specific normalization (remove dots and plus aliases)
//            if (trimmed.EndsWith("@gmail.com") || trimmed.EndsWith("@googlemail.com"))
//            {
//                var parts = trimmed.Split('@');
//                var localPart = parts[0];

//                // Remove dots
//                localPart = localPart.Replace(".", "");

//                // Remove everything after +
//                var plusIndex = localPart.IndexOf('+');
//                if (plusIndex > 0)
//                {
//                    localPart = localPart.Substring(0, plusIndex);
//                }

//                trimmed = $"{localPart}@gmail.com";
//            }

//            return trimmed;
//        }

//        private string SanitizePhoneNumber(string? phoneNumber)
//        {
//            if (string.IsNullOrWhiteSpace(phoneNumber))
//                return phoneNumber ?? string.Empty;

//            // Remove all formatting characters, keep only digits and +
//            return Regex.Replace(phoneNumber.Trim(), @"[^\d\+]", "");
//        }

//        private string? SanitizeInput(string? input, int maxLength)
//        {
//            if (string.IsNullOrWhiteSpace(input))
//                return input;

//            // Trim and limit length
//            var sanitized = input.Trim();
//            if (sanitized.Length > maxLength)
//            {
//                sanitized = sanitized.Substring(0, maxLength);
//            }

//            // Remove potential XSS/injection characters
//            sanitized = sanitized
//                .Replace("<", "")
//                .Replace(">", "")
//                .Replace("'", "'");
//                //.Replace("\"", """);

//            return sanitized;
//        }

//        // ============================================================================
//        // AUDIT LOGGING
//        // ============================================================================

//        private async Task LogAuditAsync(string? userId, string action, string? ipAddress,
//            string? userAgent, bool success, string? details, string? correlationId = null)
//        {
//            try
//            {
//                var auditLog = new AuditLog
//                {
//                    UserId = userId,
//                    Action = action,
//                    IpAddress = ipAddress,
//                    UserAgent = SanitizeInput(userAgent, 500),
//                    Success = success,
//                    Details = SanitizeInput(details, 1000),
//                    CreatedAt = DateTime.UtcNow
//                };

//                _context.AuditLogs.Add(auditLog);
//                await _context.SaveChangesAsync();

//                _logger.LogInfo("Audit log created", new
//                {
//                    CorrelationId = correlationId,
//                    UserId = userId,
//                    Action = action,
//                    Success = success
//                });
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError("Failed to create audit log", ex, new
//                {
//                    CorrelationId = correlationId,
//                    UserId = userId,
//                    Action = action
//                });
//                // Don't throw - audit logging failure shouldn't break the flow
//            }
//        }

//        // ============================================================================
//        // VALIDATION RESULT CLASS
//        // ============================================================================

//        private class ValidationResult
//        {
//            public bool IsValid { get; }
//            public string ErrorMessage { get; }

//            public ValidationResult(bool isValid, string? errorMessage = null)
//            {
//                IsValid = isValid;
//                ErrorMessage = errorMessage ?? string.Empty;
//            }
//        }

//        // ============================================================================
//        // OPERATION RESULT CLASS
//        // ============================================================================

//        public class OperationResult
//        {
//            public bool Succeeded { get; }
//            public string Message { get; }

//            private OperationResult(bool succeeded, string message = "")
//            {
//                Succeeded = succeeded;
//                Message = message;
//            }

//            public static OperationResult Success(string message = "") => new OperationResult(true, message);
//            public static OperationResult Failure(string message) => new OperationResult(false, message);
//        }


//    }
//}


//using Microsoft.EntityFrameworkCore;
//using Skills.Data;
//using Skills.Models;

//namespace Skills.Services
//{
//    public interface IBookingService
//    {
//        Task<BookingResult> CreateBookingAsync(CreateBookingRequest request);
//        Task<BookingResult> GetBookingByIdAsync(int bookingId, string userId);
//        Task<List<BookingDto>> GetUserBookingsAsync(string userId, BookingFilterRequest? filter = null);
//        Task<List<BookingDto>> GetArtisanBookingsAsync(string artisanUserId, BookingFilterRequest? filter = null);
//        Task<BookingResult> UpdateBookingStatusAsync(int bookingId, string userId, BookingStatus newStatus);
//        Task<BookingResult> CancelBookingAsync(int bookingId, string userId, string reason);
//        Task<bool> DeleteBookingAsync(int bookingId, string userId);
//    }

//    public class BookingService : IBookingService
//    {
//        private readonly AppDbContext _context;
//        private readonly INotificationService _notificationService;

//        public BookingService(AppDbContext context, INotificationService notificationService)
//        {
//            _context = context;
//            _notificationService = notificationService;
//        }

//        public async Task<BookingResult> CreateBookingAsync(CreateBookingRequest request)
//        {
//            try
//            {
//                // Validate user exists
//                var user = await _context.Users.FindAsync(request.UserId);
//                if (user == null)
//                    return BookingResult.Failure("User not found");

//                // Validate service exists and is active
//                var service = await _context.Services
//                    .Include(s => s.ArtisanProfile)
//                    .ThenInclude(a => a.User)
//                    .FirstOrDefaultAsync(s => s.Id == request.ServiceId);

//                if (service == null || !service.IsActive)
//                    return BookingResult.Failure("Service not found or inactive");

//                // Check if booking date is in the future
//                if (request.BookingDate <= DateTime.UtcNow)
//                    return BookingResult.Failure("Booking date must be in the future");

//                // Check for conflicting bookings (optional - depends on your business logic)
//                var conflictingBooking = await _context.Bookings
//                    .AnyAsync(b => b.ServiceId == request.ServiceId &&
//                                   b.BookingDate.Date == request.BookingDate.Date &&
//                                   b.Status != BookingStatus.Rejected.ToString() &&
//                                   b.Status != BookingStatus.CancelledByUser.ToString() &&
//                                   b.Status != BookingStatus.CancelledByArtisan.ToString());

//                if (conflictingBooking)
//                    return BookingResult.Failure("This time slot is already booked");

//                // Create booking
//                var booking = new Booking
//                {
//                    UserId = request.UserId,
//                    ServiceId = request.ServiceId,
//                    BookingDate = request.BookingDate,
//                    Status = BookingStatus.Pending.ToString()
//                };

//                _context.Bookings.Add(booking);
//                await _context.SaveChangesAsync();

//                // Send notification to artisan
//                await _notificationService.NotifyNewBookingAsync(
//                    service.ArtisanProfile.User.Email!,
//                    service.ArtisanProfile.User.FirstName,
//                    user.FullName,
//                    service.Name,
//                    request.BookingDate
//                );

//                var bookingDto = await MapToBookingDto(booking);
//                return BookingResult.Success(bookingDto);
//            }
//            catch (Exception ex)
//            {
//                return BookingResult.Failure($"Failed to create booking: {ex.Message}");
//            }
//        }

//        public async Task<BookingResult> GetBookingByIdAsync(int bookingId, string userId)
//        {
//            try
//            {
//                var booking = await _context.Bookings
//                    .Include(b => b.User)
//                    .Include(b => b.Service)
//                    .ThenInclude(s => s.ArtisanProfile)
//                    .ThenInclude(a => a.User)
//                    .FirstOrDefaultAsync(b => b.Id == bookingId);

//                if (booking == null)
//                    return BookingResult.Failure("Booking not found");

//                // Check if user has access to this booking
//                var isArtisan = booking.Service?.ArtisanProfile?.UserId == userId;
//                var isCustomer = booking.UserId == userId;

//                if (!isArtisan && !isCustomer)
//                    return BookingResult.Failure("Unauthorized access");

//                var bookingDto = await MapToBookingDto(booking);
//                return BookingResult.Success(bookingDto);
//            }
//            catch (Exception ex)
//            {
//                return BookingResult.Failure($"Failed to retrieve booking: {ex.Message}");
//            }
//        }

//        public async Task<List<BookingDto>> GetUserBookingsAsync(string userId, BookingFilterRequest? filter = null)
//        {
//            var query = _context.Bookings
//                .Include(b => b.Service)
//                .ThenInclude(s => s.ArtisanProfile)
//                .ThenInclude(a => a.User)
//                .Where(b => b.UserId == userId);

//            query = ApplyFilters(query, filter);

//            var bookings = await query
//                .OrderByDescending(b => b.BookingDate)
//                .ToListAsync();

//            return await Task.WhenAll(bookings.Select(MapToBookingDto));
//        }

//        public async Task<List<BookingDto>> GetArtisanBookingsAsync(string artisanUserId, BookingFilterRequest? filter = null)
//        {
//            var query = _context.Bookings
//                .Include(b => b.User)
//                .Include(b => b.Service)
//                .ThenInclude(s => s.ArtisanProfile)
//                .Where(b => b.Service!.ArtisanProfile!.UserId == artisanUserId);

//            query = ApplyFilters(query, filter);

//            var bookings = await query
//                .OrderByDescending(b => b.BookingDate)
//                .ToListAsync();

//            return await Task.WhenAll(bookings.Select(MapToBookingDto));
//        }

//        public async Task<BookingResult> UpdateBookingStatusAsync(int bookingId, string userId, BookingStatus newStatus)
//        {
//            try
//            {
//                var booking = await _context.Bookings
//                    .Include(b => b.User)
//                    .Include(b => b.Service)
//                    .ThenInclude(s => s.ArtisanProfile)
//                    .ThenInclude(a => a.User)
//                    .FirstOrDefaultAsync(b => b.Id == bookingId);

//                if (booking == null)
//                    return BookingResult.Failure("Booking not found");

//                // Check authorization
//                var isArtisan = booking.Service?.ArtisanProfile?.UserId == userId;
//                if (!isArtisan)
//                    return BookingResult.Failure("Only artisan can update booking status");

//                // Validate status transition
//                if (!IsValidStatusTransition(booking.Status, newStatus))
//                    return BookingResult.Failure($"Cannot transition from {booking.Status} to {newStatus}");

//                var oldStatus = booking.Status;
//                booking.Status = newStatus.ToString();
//                await _context.SaveChangesAsync();

//                // Send notification to user
//                await _notificationService.NotifyBookingStatusChangeAsync(
//                    booking.User!.Email!,
//                    booking.User.FirstName,
//                    booking.Service!.Name,
//                    oldStatus,
//                    newStatus.ToString()
//                );

//                var bookingDto = await MapToBookingDto(booking);
//                return BookingResult.Success(bookingDto);
//            }
//            catch (Exception ex)
//            {
//                return BookingResult.Failure($"Failed to update booking status: {ex.Message}");
//            }
//        }

//        public async Task<BookingResult> CancelBookingAsync(int bookingId, string userId, string reason)
//        {
//            try
//            {
//                var booking = await _context.Bookings
//                    .Include(b => b.User)
//                    .Include(b => b.Service)
//                    .ThenInclude(s => s.ArtisanProfile)
//                    .ThenInclude(a => a.User)
//                    .FirstOrDefaultAsync(b => b.Id == bookingId);

//                if (booking == null)
//                    return BookingResult.Failure("Booking not found");

//                // Check authorization
//                var isArtisan = booking.Service?.ArtisanProfile?.UserId == userId;
//                var isCustomer = booking.UserId == userId;

//                if (!isArtisan && !isCustomer)
//                    return BookingResult.Failure("Unauthorized access");

//                // Check if booking can be cancelled
//                if (booking.Status == BookingStatus.Completed.ToString() ||
//                    booking.Status == BookingStatus.CancelledByUser.ToString() ||
//                    booking.Status == BookingStatus.CancelledByArtisan.ToString())
//                {
//                    return BookingResult.Failure("Booking cannot be cancelled in current state");
//                }

//                var newStatus = isCustomer ? BookingStatus.CancelledByUser : BookingStatus.CancelledByArtisan;
//                booking.Status = newStatus.ToString();
//                await _context.SaveChangesAsync();

//                // Notify the other party
//                if (isCustomer)
//                {
//                    await _notificationService.NotifyBookingCancelledAsync(
//                        booking.Service!.ArtisanProfile!.User.Email!,
//                        booking.Service.ArtisanProfile.User.FirstName,
//                        booking.User!.FullName,
//                        booking.Service.Name,
//                        reason
//                    );
//                }
//                else
//                {
//                    await _notificationService.NotifyBookingCancelledAsync(
//                        booking.User!.Email!,
//                        booking.User.FirstName,
//                        booking.Service!.ArtisanProfile!.User.FullName,
//                        booking.Service.Name,
//                        reason
//                    );
//                }

//                var bookingDto = await MapToBookingDto(booking);
//                return BookingResult.Success(bookingDto);
//            }
//            catch (Exception ex)
//            {
//                return BookingResult.Failure($"Failed to cancel booking: {ex.Message}");
//            }
//        }

//        public async Task<bool> DeleteBookingAsync(int bookingId, string userId)
//        {
//            try
//            {
//                var booking = await _context.Bookings
//                    .Include(b => b.Service)
//                    .ThenInclude(s => s.ArtisanProfile)
//                    .FirstOrDefaultAsync(b => b.Id == bookingId);

//                if (booking == null)
//                    return false;

//                // Only allow deletion of own bookings that are cancelled or rejected
//                if (booking.UserId != userId)
//                    return false;

//                if (booking.Status != BookingStatus.CancelledByUser.ToString() &&
//                    booking.Status != BookingStatus.Rejected.ToString())
//                {
//                    return false;
//                }

//                _context.Bookings.Remove(booking);
//                await _context.SaveChangesAsync();

//                return true;
//            }
//            catch
//            {
//                return false;
//            }
//        }

//        // Helper methods
//        private IQueryable<Booking> ApplyFilters(IQueryable<Booking> query, BookingFilterRequest? filter)
//        {
//            if (filter == null)
//                return query;

//            if (!string.IsNullOrEmpty(filter.Status))
//                query = query.Where(b => b.Status == filter.Status);

//            if (filter.FromDate.HasValue)
//                query = query.Where(b => b.BookingDate >= filter.FromDate.Value);

//            if (filter.ToDate.HasValue)
//                query = query.Where(b => b.BookingDate <= filter.ToDate.Value);

//            if (filter.ServiceId.HasValue)
//                query = query.Where(b => b.ServiceId == filter.ServiceId.Value);

//            return query;
//        }

//        private bool IsValidStatusTransition(string currentStatus, BookingStatus newStatus)
//        {
//            // Define valid status transitions
//            var validTransitions = new Dictionary<string, List<BookingStatus>>
//            {
//                [BookingStatus.Pending.ToString()] = new() { BookingStatus.Accepted, BookingStatus.Rejected, BookingStatus.Expired },
//                [BookingStatus.Accepted.ToString()] = new() { BookingStatus.InProgress, BookingStatus.CancelledByArtisan, BookingStatus.NoShow },
//                [BookingStatus.InProgress.ToString()] = new() { BookingStatus.Completed, BookingStatus.Failed },
//                [BookingStatus.Completed.ToString()] = new() { BookingStatus.Disputed }
//            };

//            return validTransitions.ContainsKey(currentStatus) &&
//                   validTransitions[currentStatus].Contains(newStatus);
//        }

//        private async Task<BookingDto> MapToBookingDto(Booking booking)
//        {
//            return new BookingDto
//            {
//                Id = booking.Id,
//                UserId = booking.UserId,
//                ServiceId = booking.ServiceId,
//                BookingDate = booking.BookingDate,
//                Status = booking.Status,
//                UserName = booking.User?.FullName ?? string.Empty,
//                UserEmail = booking.User?.Email ?? string.Empty,
//                UserPhone = booking.User?.PhoneNumber ?? string.Empty,
//                ServiceName = booking.Service?.Name ?? string.Empty,
//                ServiceCategory = booking.Service?.Category ?? string.Empty,
//                ArtisanName = booking.Service?.ArtisanProfile?.User.FullName ?? string.Empty,
//                ArtisanEmail = booking.Service?.ArtisanProfile?.User.Email ?? string.Empty,
//                ArtisanPhone = booking.Service?.ArtisanProfile?.User.PhoneNumber ?? string.Empty,
//                BusinessName = booking.Service?.ArtisanProfile?.BusinessName
//            };
//        }
//    }

//    // DTOs
//    public class CreateBookingRequest
//    {
//        public string UserId { get; set; } = string.Empty;
//        public Guid ServiceId { get; set; }
//        public DateTime BookingDate { get; set; }
//    }

//    public class BookingFilterRequest
//    {
//        public string? Status { get; set; }
//        public DateTime? FromDate { get; set; }
//        public DateTime? ToDate { get; set; }
//        public Guid? ServiceId { get; set; }
//    }

//    public class BookingDto
//    {
//        public int Id { get; set; }
//        public string UserId { get; set; } = string.Empty;
//        public Guid ServiceId { get; set; }
//        public DateTime BookingDate { get; set; }
//        public string Status { get; set; } = string.Empty;
//        public string UserName { get; set; } = string.Empty;
//        public string UserEmail { get; set; } = string.Empty;
//        public string UserPhone { get; set; } = string.Empty;
//        public string ServiceName { get; set; } = string.Empty;
//        public string ServiceCategory { get; set; } = string.Empty;
//        public string ArtisanName { get; set; } = string.Empty;
//        public string ArtisanEmail { get; set; } = string.Empty;
//        public string ArtisanPhone { get; set; } = string.Empty;
//        public string? BusinessName { get; set; }
//    }

//    public class BookingResult
//    {
//        public bool Succeeded { get; set; }
//        public BookingDto? Booking { get; set; }
//        public string? Error { get; set; }

//        public static BookingResult Success(BookingDto booking)
//        {
//            return new BookingResult
//            {
//                Succeeded = true,
//                Booking = booking
//            };
//        }

//        public static BookingResult Failure(string error)
//        {
//            return new BookingResult
//            {
//                Succeeded = false,
//                Error = error
//            };
//        }
//    }

//    // Notification service interface
//    public interface INotificationService
//    {
//        Task NotifyNewBookingAsync(string email, string name, string customerName, string serviceName, DateTime bookingDate);
//        Task NotifyBookingStatusChangeAsync(string email, string name, string serviceName, string oldStatus, string newStatus);
//        Task NotifyBookingCancelledAsync(string email, string name, string cancelledBy, string serviceName, string reason);
//    }
//}