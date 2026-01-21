using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Skills.Data;
using Skills.Models;
using Skills.DTOs;

namespace Skills.Services
{
    public interface IAuthService
    {
        Task<AuthResult> RegisterAsync(RegisterRequest request);
        Task<AuthResult> EmailVerifyAsync(VerifyEmailRequest request);
        Task<AuthResult> ResendVerificationCodeEndpointAsync(ResendCodeRequest request);
        Task<AuthResult> LoginAsync(LoginRequest request);
        Task<AuthResult> RefreshTokenAsync(string refreshToken);
        Task<bool> RevokeTokenAsync(string refreshToken);
        Task<bool> SendPasswordResetTokenAsync(string email);
        Task<bool> ResetPasswordAsync(ResetPasswordRequest request);
        Task<bool> ChangePasswordAsync(string userId, ChangePasswordRequest request);
        Task<bool> SendEmailVerificationTokenAsync(string userId);
        Task<bool> VerifyEmailAsync(string token);
        //Task<bool> SendOtpAsync(string phoneNumber);
        Task<bool> VerifyOtpAsync(string phoneNumber, string otp);
        // Task<OperationResult> GenerateAndSendVerificationCodeAsync(string userId, string email);
        // Task<OperationResult> ResendVerificationCodeAsync(string userId, string email);
    }

    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly ILoggingService _logger;
        //private readonly ISmsService _smsService;

        public AuthService(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            AppDbContext context,
            IConfiguration configuration,
            IEmailService emailService,
            ILoggingService loggingService
            //ISmsService smsService
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _context = context;
            _configuration = configuration;
            _emailService = emailService;
            _logger = loggingService;
            //_smsService = smsService;
        }

        public async Task<AuthResult> RegisterAsync(RegisterRequest request)
        {
            try
            {
                // Validate input
                var validationResult = ValidateUserRegistrationInput(request);
                if (!validationResult.IsValid)
                {
                    return AuthResult.Failure(validationResult.ErrorMessage);
                }

                var normalizedEmail = request.Email.Trim().ToLowerInvariant();

                // Check if user already exists
                var existingUser = await _userManager.FindByEmailAsync(normalizedEmail);
                if (existingUser != null)
                {
                    // If email is already verified, they should login instead
                    if (existingUser.EmailVerified)
                    {
                        return AuthResult.Failure("An account with this email already exists. Please login.");
                    }

                    if (existingUser.Email == null)
                    {
                        return AuthResult.Failure("Invalid Account");
                    }

                    // User exists but email not verified - update their details and resend verification
                    await using var transaction = await _context.Database.BeginTransactionAsync();

                    try
                    {
                        // Update basic user information
                        existingUser.FirstName = request.FirstName;
                        existingUser.LastName = request.LastName;
                        existingUser.PhoneNumber = request.PhoneNumber;
                        existingUser.UserType = request.UserType;
                        existingUser.UpdatedAt = DateTime.UtcNow;

                        // Update password
                        var removePasswordResult = await _userManager.RemovePasswordAsync(existingUser);
                        if (removePasswordResult.Succeeded)
                        {
                            var addPasswordResult = await _userManager.AddPasswordAsync(existingUser, request.Password);
                            if (!addPasswordResult.Succeeded)
                            {
                                return AuthResult.Failure("Failed to update password");
                            }
                        }

                        // Update role if UserType changed
                        var currentRoles = await _userManager.GetRolesAsync(existingUser);
                        var newRoleName = request.UserType.ToString();

                        if (!await _roleManager.RoleExistsAsync(newRoleName))
                        {
                            return AuthResult.Failure("Invalid role");
                        }

                        if (!currentRoles.Contains(newRoleName))
                        {
                            if (currentRoles.Any())
                            {
                                await _userManager.RemoveFromRolesAsync(existingUser, currentRoles);
                            }
                            var roleResult = await _userManager.AddToRoleAsync(existingUser, newRoleName);
                            if (!roleResult.Succeeded)
                            {
                                return AuthResult.Failure("Failed to assign user role");
                            }
                        }

                        // Update type-specific data
                        if (request.UserType == UserType.User)
                        {
                            // Remove old artisan profile and services if switching from Artisan to User
                            var oldArtisanProfile = await _context.ArtisanProfiles
                                .FirstOrDefaultAsync(ap => ap.UserId == existingUser.Id);

                            if (oldArtisanProfile != null)
                            {
                                var oldServices = await _context.Services
                                    .Where(s => s.ArtisanId == oldArtisanProfile.Id)
                                    .ToListAsync();
                                _context.Services.RemoveRange(oldServices);
                                _context.ArtisanProfiles.Remove(oldArtisanProfile);
                            }

                            // Remove old preferences
                            var oldPreferences = await _context.ServicePreferences
                                .Where(sp => sp.UserId == existingUser.Id)
                                .ToListAsync();
                            _context.ServicePreferences.RemoveRange(oldPreferences);

                            // Add new preferences
                            if (request.ServicePreferences?.Any() == true)
                            {
                                var newPreferences = request.ServicePreferences.Select(sp => new ServicePreference
                                {
                                    UserId = existingUser.Id,
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
                                .Where(sp => sp.UserId == existingUser.Id)
                                .ToListAsync();
                            _context.ServicePreferences.RemoveRange(oldPreferences);

                            // Update or create artisan profile
                            var existingProfile = await _context.ArtisanProfiles
                                .FirstOrDefaultAsync(ap => ap.UserId == existingUser.Id);

                            if (existingProfile != null)
                            {
                                existingProfile.BusinessName = request.BusinessName;
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
                                    UserId = existingUser.Id,
                                    BusinessName = request.BusinessName,
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
                                    Name = request.Service.Name,
                                    Category = request.Service.Category,
                                    PricingModel = request.Service.PricingModel,
                                    MinPrice = request.Service.MinPrice,
                                    MaxPrice = request.Service.MaxPrice,
                                    Availability = request.Service.Availability,
                                    Notes = request.Service.Notes,
                                    CreatedAt = DateTime.UtcNow,
                                    UpdatedAt = DateTime.UtcNow
                                };
                                _context.Services.Add(service);
                            }
                        }

                        // Save all changes
                        await _context.SaveChangesAsync();

                        // Resend verification code
                        var resendResult = await ResendVerificationCodeAsync(existingUser.Id, existingUser.Email);
                        if (!resendResult.Succeeded)
                        {
                            await transaction.RollbackAsync();
                            return AuthResult.Failure("Failed to send verification code. Please try again.");
                        }

                        // Commit transaction
                        await transaction.CommitAsync();

                        // Log audit
                        await LogAuditAsync(
                            existingUser.Id,
                            "Registration Update",
                            null,
                            null,
                            true,
                            $"User updated registration details as {request.UserType} - verification code resent"
                        );

                        // Return success with pending verification status
                        return AuthResult.PendingVerification(
                            userId: existingUser.Id,
                            email: existingUser.Email,
                            message: "Your registration details have been updated. A verification code has been sent to your email."
                        );
                    }
                    catch (Exception transactionEx)
                    {
                        await transaction.RollbackAsync();
                        _logger.LogError("Transaction failed during registration update for {Email}", transactionEx,
                            new { Email = normalizedEmail });
                        throw;
                    }
                }

                // Check phone number uniqueness
                var phoneExists = await _context.Users.AnyAsync(u => u.PhoneNumber == request.PhoneNumber);
                if (phoneExists)
                {
                    return AuthResult.Failure("User with this phone number already exists");
                }

                
                await using var newUserTransaction = await _context.Database.BeginTransactionAsync();

                try
                {
                    // Create user
                    var user = new ApplicationUser
                    {
                        UserName = normalizedEmail,
                        Email = normalizedEmail,
                        FirstName = request.FirstName,
                        LastName = request.LastName,
                        PhoneNumber = request.PhoneNumber,
                        UserType = request.UserType,
                        Status = UserStatus.Pending,
                        EmailVerified = false,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };

                    var createResult = await _userManager.CreateAsync(user, request.Password);
                    if (!createResult.Succeeded)
                    {
                        return AuthResult.Failure(string.Join(", ", createResult.Errors.Select(e => e.Description)));
                    }

                    // Assign role
                    var roleName = request.UserType.ToString();
                    if (!await _roleManager.RoleExistsAsync(roleName))
                    {
                        return AuthResult.Failure("Invalid role");
                    }

                    var roleResult = await _userManager.AddToRoleAsync(user, roleName);
                    if (!roleResult.Succeeded)
                    {
                        return AuthResult.Failure("Failed to assign user role");
                    }

                    // Handle user type-specific data
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
                            BusinessName = request.BusinessName,
                            CreatedAt = DateTime.UtcNow,
                            UpdatedAt = DateTime.UtcNow
                        };
                        _context.ArtisanProfiles.Add(artisanProfile);

                        // Add artisan's first service using navigation property
                        if (request.Service != null)
                        {
                            var service = new Service
                            {
                                ArtisanId = artisanProfile.Id,
                                Name = request.Service.Name,
                                Category = request.Service.Category,
                                PricingModel = request.Service.PricingModel,
                                MinPrice = request.Service.MinPrice,
                                MaxPrice = request.Service.MaxPrice,
                                Availability = request.Service.Availability,
                                Notes = request.Service.Notes,
                                CreatedAt = DateTime.UtcNow,
                                UpdatedAt = DateTime.UtcNow
                            };
                            _context.Services.Add(service);
                        }
                    }

                    // Single SaveChanges for all related entities
                    await _context.SaveChangesAsync();

                    // Generate and send verification code
                    var verificationResult = await GenerateAndSendVerificationCodeAsync(user.Id, user.Email);
                    if (!verificationResult.Succeeded)
                    {
                        // Still commit the transaction but log the email failure
                        await newUserTransaction.CommitAsync();
                        return AuthResult.Failure("Account created but failed to send verification email. Please request a new code.");
                    }

                    // Commit transaction
                    await newUserTransaction.CommitAsync();

                    // Log audit
                    await LogAuditAsync(
                        user.Id,
                        "Registration",
                        null,
                        null,
                        true,
                        $"User registered as {request.UserType} - pending email verification"
                    );

                    // Return success with pending verification status
                    return AuthResult.PendingVerification(
                        userId: user.Id,
                        email: user.Email,
                        message: "Registration successful. Please check your email for the verification code."
                    );
                }
                catch (Exception transactionEx)
                {
                    await newUserTransaction.RollbackAsync();
                    _logger.LogError("Transaction failed during user registration for {Email}", transactionEx,
                        new { Email = normalizedEmail });
                    throw;
                }
            }
            catch (Exception ex)
            {
                return AuthResult.Failure($"Registration failed: {ex.Message}");
            }
        }

        public async Task<AuthResult> EmailVerifyAsync(VerifyEmailRequest request)
        {
                var normalizedEmail = request.Email.Trim().ToLowerInvariant();
            try
            {

                var user = await _userManager.FindByEmailAsync(normalizedEmail);
                // var user = await _userManager.FindByIdAsync(request.UserId);
                if (user == null)
                {
                    return AuthResult.Failure("Invalid verification request");
                }

                if (user.EmailVerified)
                {
                    return AuthResult.Failure("Email already verified. Please login.");
                }

                // Find the verification token
                var verificationToken = await _context.EmailVerificationTokens
                    .Where(t => t.Email == request.Email &&
                            t.TokenHash == request.Code &&
                            !t.Used &&
                            t.ExpiresAt > DateTime.UtcNow)
                    .OrderByDescending(t => t.CreatedAt)
                    .FirstOrDefaultAsync();

                if (verificationToken == null)
                {
                    // Check if code is expired
                    var expiredToken = await _context.EmailVerificationTokens
                        .Where(t => t.Email == request.Email &&
                                t.TokenHash == request.Code &&
                                !t.Used)
                        .FirstOrDefaultAsync();

                    if (expiredToken != null)
                    {
                        return AuthResult.Failure("Verification code has expired. Please request a new one.");
                    }

                    return AuthResult.Failure("Invalid verification code");
                }

                // Mark token as used
                verificationToken.Used = true;
                verificationToken.UsedAt = DateTime.UtcNow;

                // Update user status
                user.EmailVerified = true;
                user.Status = UserStatus.Active;
                user.UpdatedAt = DateTime.UtcNow;

                await _context.SaveChangesAsync();

                // Log audit
                await LogAuditAsync(
                    user.Id,
                    "EmailVerification",
                    null,
                    null,
                    true,
                    "Email verified successfully"
                );

                // Generate tokens for authenticated session
                var accessToken = GenerateAccessToken(user);
                var refreshToken = await GenerateRefreshTokenAsync(
                    user.Id,
                    request.DeviceInfo,
                    request.IpAddress
                );

                return AuthResult.Success(accessToken, refreshToken, user);
            }
            catch (Exception ex)
            {
                _logger.LogError("Email verification failed for user {UserId}", ex,
            new { Email = normalizedEmail });
                return AuthResult.Failure("Verification failed. Please try again.");
            }
        }

        public async Task<AuthResult> ResendVerificationCodeEndpointAsync(ResendCodeRequest request)
        {
                var normalizedEmail = request.Email.Trim().ToLowerInvariant();
            try
            {

                var user = await _userManager.FindByEmailAsync(normalizedEmail);
                if (user == null)
                {
                    return AuthResult.Failure("User not found");
                }

                if (user.EmailVerified)
                {
                    return AuthResult.Failure("Email already verified. Please login.");
                }


                if (user.Email == null)
                {
                    return AuthResult.Failure("Invalid Account");
                }

                var result = await ResendVerificationCodeAsync(user.Id, user.Email);
                if (!result.Succeeded)
                {
                    return AuthResult.Failure(result.Message);
                }

                return AuthResult.PendingVerification(
                    userId: user.Id,
                    email: user.Email,
                    message: "Verification code has been resent to your email."
                );
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to resend verification code", ex,
          new { Email = normalizedEmail });
                return AuthResult.Failure("Failed to send verification code");
            }
        }

        public async Task<AuthResult> LoginAsync(LoginRequest request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                    return AuthResult.Failure("Invalid email or password");

                if (!user.IsActive)
                    return AuthResult.Failure("Account is inactive");

                if (user.Status != UserStatus.Active)
                    return AuthResult.Failure($"Account is {user.Status.ToString().ToLower()}");

                var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
                if (!passwordValid)
                {
                    await LogAuditAsync(user.Id, "Login", request.IpAddress, request.UserAgent, false, "Invalid password");
                    return AuthResult.Failure("Invalid email or password");
                }

                // Update last login
                user.LastLoginAt = DateTime.UtcNow;
                user.UpdatedAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                // Generate tokens
                var accessToken = GenerateAccessToken(user);
                var refreshToken = await GenerateRefreshTokenAsync(user.Id, request.DeviceInfo, request.IpAddress);

                // Log audit
                await LogAuditAsync(user.Id, "Login", request.IpAddress, request.UserAgent, true, "Successful login");

                return AuthResult.Success(accessToken, refreshToken, user);
            }
            catch (Exception ex)
            {
                return AuthResult.Failure($"Login failed: {ex.Message}");
            }
        }

        public async Task<AuthResult> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashToken(refreshToken);
                var storedToken = await _context.RefreshTokens
                    .Include(t => t.User)
                    .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && !t.Revoked);

                if (storedToken == null)
                    return AuthResult.Failure("Invalid refresh token");

                if (storedToken.ExpiresAt < DateTime.UtcNow)
                {
                    storedToken.Revoked = true;
                    storedToken.RevokedAt = DateTime.UtcNow;
                    storedToken.RevokedReason = "Token expired";
                    await _context.SaveChangesAsync();
                    return AuthResult.Failure("Refresh token expired");
                }

                var user = storedToken.User;
                if (!user.IsActive)
                    return AuthResult.Failure("Account is inactive");

                // Generate new tokens
                var accessToken = GenerateAccessToken(user);
                var newRefreshToken = await GenerateRefreshTokenAsync(user.Id, storedToken.DeviceInfo, storedToken.IpAddress);

                // Revoke old refresh token
                storedToken.Revoked = true;
                storedToken.RevokedAt = DateTime.UtcNow;
                storedToken.RevokedReason = "Token refreshed";
                await _context.SaveChangesAsync();

                return AuthResult.Success(accessToken, newRefreshToken, user);
            }
            catch (Exception ex)
            {
                return AuthResult.Failure($"Token refresh failed: {ex.Message}");
            }
        }

        public async Task<bool> RevokeTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashToken(refreshToken);
                var storedToken = await _context.RefreshTokens
                    .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && !t.Revoked);

                if (storedToken == null)
                    return false;

                storedToken.Revoked = true;
                storedToken.RevokedAt = DateTime.UtcNow;
                storedToken.RevokedReason = "User logout";
                await _context.SaveChangesAsync();

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> SendPasswordResetTokenAsync(string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                    return true; // Don't reveal if email exists

                var token = GenerateSecureToken();
                var tokenHash = HashToken(token);

                var resetToken = new PasswordResetToken
                {
                    UserId = user.Id,
                    TokenHash = tokenHash,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    CreatedAt = DateTime.UtcNow
                };

                _context.PasswordResetTokens.Add(resetToken);
                await _context.SaveChangesAsync();

                // Send email
                if (string.IsNullOrWhiteSpace(user.Email))
                {
                    return true;
                }
                ;

                //await _emailService.SendPasswordResetEmailAsync(user.Email, user.FirstName, token);
                await _emailService.SendPasswordResetAsync(user.Email, token);

                await LogAuditAsync(user.Id, "PasswordResetRequest", null, null, true, "Password reset requested");

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request)
        {
            try
            {
                var tokenHash = HashToken(request.Token);
                var resetToken = await _context.PasswordResetTokens
                    .Include(t => t.User)
                    .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && !t.Used);

                if (resetToken == null || resetToken.ExpiresAt < DateTime.UtcNow)
                    return false;

                var user = resetToken.User;
                var resetPasswordResult = await _userManager.RemovePasswordAsync(user);
                if (!resetPasswordResult.Succeeded)
                    return false;

                var addPasswordResult = await _userManager.AddPasswordAsync(user, request.NewPassword);
                if (!addPasswordResult.Succeeded)
                    return false;

                // Mark token as used
                resetToken.Used = true;
                user.UpdatedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                // Revoke all refresh tokens
                var tokens = await _context.RefreshTokens.Where(t => t.UserId == user.Id && !t.Revoked).ToListAsync();
                foreach (var token in tokens)
                {
                    token.Revoked = true;
                    token.RevokedAt = DateTime.UtcNow;
                    token.RevokedReason = "Password reset";
                }
                await _context.SaveChangesAsync();

                await LogAuditAsync(user.Id, "PasswordReset", null, null, true, "Password reset successfully");

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> ChangePasswordAsync(string userId, ChangePasswordRequest request)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                    return false;

                var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
                if (!result.Succeeded)
                    return false;

                user.UpdatedAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                await LogAuditAsync(user.Id, "PasswordChange", null, null, true, "Password changed successfully");

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> SendEmailVerificationTokenAsync(string userId)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null || user.EmailVerified)
                    return false;

                var token = GenerateSecureToken();
                var tokenHash = HashToken(token);

                if (string.IsNullOrWhiteSpace(user.Email))
                {
                    return true;
                }

                var verificationToken = new EmailVerificationToken
                {
                    UserId = user.Id,
                    Email = user.Email,
                    TokenHash = tokenHash,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    CreatedAt = DateTime.UtcNow
                };

                _context.EmailVerificationTokens.Add(verificationToken);
                await _context.SaveChangesAsync();

                // Send email

                ;
                //await _emailService.SendEmailVerificationAsync(user.Email, user.FirstName, token);
                await _emailService.SendEmailVerificationAsync(user.Email, token);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> VerifyEmailAsync(string token)
        {
            try
            {
                var tokenHash = HashToken(token);
                var verificationToken = await _context.EmailVerificationTokens
                    .Include(t => t.User)
                    .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && !t.Used);

                if (verificationToken == null || verificationToken.ExpiresAt < DateTime.UtcNow)
                    return false;

                var user = verificationToken.User;
                user.EmailVerified = true;
                user.Status = UserStatus.Active;
                user.UpdatedAt = DateTime.UtcNow;

                verificationToken.Used = true;
                await _context.SaveChangesAsync();

                await LogAuditAsync(user.Id, "EmailVerification", null, null, true, "Email verified successfully");

                return true;
            }
            catch
            {
                return false;
            }
        }

        //public async Task<bool> SendOtpAsync(string phoneNumber)
        //{
        //    try
        //    {
        //        var otp = GenerateOtp();
        //        var otpHash = HashToken(otp);

        //        // Store OTP in cache or database (using email verification token table for example)
        //        var user = await _context.Users.FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber);
        //        if (user == null)
        //            return false;

        //        var otpToken = new EmailVerificationToken // Reusing for OTP
        //        {
        //            UserId = user.Id,
        //            TokenHash = otpHash,
        //            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
        //            CreatedAt = DateTime.UtcNow
        //        };

        //        _context.EmailVerificationTokens.Add(otpToken);
        //        await _context.SaveChangesAsync();

        //        // Send SMS
        //        await _smsService.SendOtpAsync(phoneNumber, otp);

        //        return true;
        //    }
        //    catch
        //    {
        //        return false;
        //    }
        //}

        public async Task<bool> VerifyOtpAsync(string phoneNumber, string otp)
        {
            try
            {
                var otpHash = HashToken(otp);
                var user = await _context.Users.FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber);
                if (user == null)
                    return false;

                var otpToken = await _context.EmailVerificationTokens
                    .FirstOrDefaultAsync(t => t.UserId == user.Id && t.TokenHash == otpHash && !t.Used);

                if (otpToken == null || otpToken.ExpiresAt < DateTime.UtcNow)
                    return false;

                otpToken.Used = true;
                await _context.SaveChangesAsync();

                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<OperationResult> GenerateAndSendVerificationCodeAsync(string userId, string email)
        {
            try
            {
                // Generate 6-digit code
                var code = GenerateVerificationCode();
                var expiryTime = DateTime.UtcNow.AddMinutes(15); // Code expires in 15 minutes

                // Store verification code in database
                var verificationToken = new EmailVerificationToken
                {
                    UserId = userId,
                    Email = email,
                    TokenHash = code,
                    ExpiresAt = expiryTime,
                    Used = false,
                    CreatedAt = DateTime.UtcNow
                };

                // Invalidate any previous unused codes for this user
                var existingTokens = await _context.EmailVerificationTokens
                    .Where(t => t.Email == email && !t.Used)
                    .ToListAsync();

                foreach (var token in existingTokens)
                {
                    token.Used = true; // Mark as used/invalidated
                }

                _context.EmailVerificationTokens.Add(verificationToken);
                await _context.SaveChangesAsync();

                // Send email with verification code
                await _emailService.SendEmailVerificationAsync(email, code);

                //await _emailService.SendVerificationCodeAsync(email, code, expiryTime);

                return OperationResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to generate and send verification code for user {UserId}", ex,
         new { User = userId });
                return OperationResult.Failure("Failed to send verification code");
            }
        }

        private async Task<OperationResult> ResendVerificationCodeAsync(string userId, string email)
        {
            try
            {
                // Check rate limiting - prevent spam
                var recentToken = await _context.EmailVerificationTokens
                    .Where(t => t.UserId == userId)
                    .OrderByDescending(t => t.CreatedAt)
                    .FirstOrDefaultAsync();

                if (recentToken != null && recentToken.CreatedAt.AddMinutes(1) > DateTime.UtcNow)
                {
                    return OperationResult.Failure("Please wait before requesting a new code");
                }

                return await GenerateAndSendVerificationCodeAsync(userId, email);
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to resend verification code for user {UserId}", ex,
        new { User = userId });
                return OperationResult.Failure("Failed to send verification code");
            }
        }

        private string GenerateVerificationCode()
        {
            // Generate a secure 6-digit code
            var random = new Random();
            return random.Next(100000, 999999).ToString();

            // Or use cryptographically secure random:
            // using var rng = RandomNumberGenerator.Create();
            // var bytes = new byte[4];
            // rng.GetBytes(bytes);
            // var code = BitConverter.ToUInt32(bytes, 0) % 1000000;
            // return code.ToString("D6");
        }

        // Helper methods
        private string GenerateAccessToken(ApplicationUser user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim("userType", user.UserType.ToString()),
                new Claim("fullName", user.FullName)
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryMinutes"])),
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
                DeviceInfo = deviceInfo,
                IpAddress = ipAddress,
                ExpiresAt = DateTime.UtcNow.AddDays(Convert.ToDouble(_configuration["Jwt:RefreshTokenExpiryDays"] ?? "30")),
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

        private string GenerateOtp()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        private static string GenerateOtpCode()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            var number = Math.Abs(BitConverter.ToInt32(bytes, 0));
            return (number % 1000000).ToString("D6");
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashBytes);
        }

        private async Task LogAuditAsync(string? userId, string action, string? ipAddress, string? userAgent, bool success, string? details)
        {
            var auditLog = new AuditLog
            {
                UserId = userId,
                Action = action,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                Success = success,
                Details = details,
                CreatedAt = DateTime.UtcNow
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }


        private ValidationResult ValidateUserRegistrationInput(RegisterRequest request)
        {

            if (string.IsNullOrWhiteSpace(request.Email) || !new EmailAddressAttribute().IsValid(request.Email))
                return new ValidationResult(false, "Please provide a valid email address");


            if (string.IsNullOrWhiteSpace(request.Password))
                return new ValidationResult(false, "Password is required");

            if (string.IsNullOrWhiteSpace(request.FirstName))
                return new ValidationResult(false, "FirstName is required");

            if (string.IsNullOrWhiteSpace(request.LastName))
                return new ValidationResult(false, "LastName is required");

            if (string.IsNullOrWhiteSpace(request.PhoneNumber))
                return new ValidationResult(false, "PhoneNumber is required");

            if (!Enum.IsDefined(typeof(UserType), request.UserType))
                return new ValidationResult(false, "UserType is required");

            if (request.UserType == UserType.Artisan)
            {
                if (string.IsNullOrWhiteSpace(request.BusinessName))
                {
                    return new ValidationResult(false, "Business name is required for artisan registration");
                }

                if (request.Service == null)
                {
                    return new ValidationResult(false, "At least one service is required for artisan registration");
                }

                // Validate service details
                if (string.IsNullOrWhiteSpace(request.Service.Name))
                {
                    return new ValidationResult(false, "Service name is required");
                }

                if (request.Service.Category == null || string.IsNullOrWhiteSpace(request.Service.Category))
                {
                    return new ValidationResult(false, "Service category is required");
                }

                if (!Enum.IsDefined(typeof(PricingModel), request.Service.PricingModel))

                    //if (request.Service.PricingModel == null || request.Service.PricingModel == 0)
                {
                    return new ValidationResult(false, "Pricing model is required");
                }
            }


            return new ValidationResult(true);
        }

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

    }
}