using Skills.Models;
using System.ComponentModel.DataAnnotations;

namespace Skills.DTOs
{
    public class LoginRequest
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required, MinLength(6)]
        public string Password { get; set; } = string.Empty;

        public string? DeviceInfo { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }

    }

    public class RegisterRequest
    {
        // Common fields
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required, MinLength(6)]
        public string Password { get; set; } = string.Empty;

        [Required, MaxLength(100)]
        public string FirstName { get; set; } = string.Empty;

        [Required, MaxLength(100)]
        public string LastName { get; set; } = string.Empty;

        [Required, MaxLength(20)]
        public string PhoneNumber { get; set; } = string.Empty;

        [Required]
        public UserType UserType { get; set; }

        // User-specific
        public string? FullName { get; set; }
        public List<string>? ServicePreferences { get; set; }

        // Artisan-specific
        public string? BusinessName { get; set; }
        public ServiceRequest? Service { get; set; }

        // Device tracking
        public string? DeviceInfo { get; set; }
        public string? IpAddress { get; set; }
    }

    public class VerifyEmailRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string? DeviceInfo { get; set; }
        public string? IpAddress { get; set; }
    }

    public class ResendCodeRequest
    {
        public string Email { get; set; } = string.Empty;
        public string? DeviceInfo { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
    }

    public class ServiceRequest
    {
        public string Name { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public PricingModel PricingModel { get; set; }
        public decimal? MinPrice { get; set; }
        public decimal? MaxPrice { get; set; }
        public string Availability { get; set; } = string.Empty;
        public string? Notes { get; set; }
    }

    public class ResetPasswordRequest
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;

        public string Token { get; set; } = string.Empty;

        [Required, MinLength(6)]
        public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangePasswordRequest
    {
        [Required, MinLength(6)]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required, MinLength(6)]
        public string NewPassword { get; set; } = string.Empty;
    }

    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
    }

    public class ForgotPasswordRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    public class SendOtpRequest
    {
        public string PhoneNumber { get; set; } = string.Empty;
    }

    public class VerifyOtpRequest
    {
        public string PhoneNumber { get; set; } = string.Empty;
        public string Otp { get; set; } = string.Empty;
    }

    public class AuthResult
    {
        public int StatusCode { get; set; }
        public bool Succeeded { get; set; }
        public string? Message { get; set; }
        public UserTokenDTO? Data { get; set; }
        public string? Error { get; set; }

        public static AuthResult Success(
            string accessToken,
            string refreshToken,
            ApplicationUser user)
        {
            return new AuthResult
            {
                StatusCode = 200,
                Succeeded = true,
                Message = "User Authenticated Successfully!",
                Data = new UserTokenDTO
                {
                    Token = accessToken,
                    RefreshToken = refreshToken,
                    User = UserDTO.FromUser(user)
                }
            };
        }

        public static AuthResult PendingVerification(string userId, string email, string message)
        {
            return new AuthResult
            {
                StatusCode = 429,
                Succeeded = true,
                //IsPendingVerification = true,
                //UserId = userId,
                //Email = email,
                Message = message,
                Data = null
            };
        }

        public static AuthResult Failure(string message)
        {
            return new AuthResult
            {
                StatusCode = 400,
                Succeeded = false,
                Message = "Authentication Failed",
                Data = null,
                //Data = new UserTokenDTO<null>
                Error = message
            };
        }
    }


    public class UserTokenDTO
    {
        public UserDTO User { get; set; } = null!;

        public string Token { get; set; } = string.Empty;

        public string? RefreshToken { get; set; }
    }

    public class UserDTO
    {
        public string Id { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public UserType UserType { get; set; }

        public string FirstName { get; set; } = string.Empty;

        public string LastName { get; set; } = string.Empty;

        public string? FullName { get; set; }

        public string PhoneNumber { get; set; } = string.Empty;

        public string? ProfilePhoto { get; set; }

        // User-specific
        public ICollection<ServicePreference>? ServicePreferences { get; set; }

        // Artisan-specific
        public string? BusinessName { get; set; }

        public List<ServiceDTO>? Services { get; set; }

        public static UserDTO FromUser(ApplicationUser user)
        {
            return new UserDTO
            {
                Id = user.Id,
                Email = user.Email!,
                UserType = user.UserType,
                FirstName = user.FirstName,
                LastName = user.LastName,
                FullName = user.FullName,
                PhoneNumber = user.PhoneNumber!,
                ProfilePhoto = user.ProfilePhoto,
                BusinessName = user.ArtisanProfile?.BusinessName,
                ServicePreferences = user.UserPreferences
            };
        }
    }

    public class ServiceDTO
    {
        public string Id { get; set; } = string.Empty;

        public string Name { get; set; } = string.Empty;

        public string Category { get; set; } = string.Empty;

        public PricingModel PricingModel { get; set; }

        public decimal? MinPrice { get; set; }

        public decimal? MaxPrice { get; set; }

        public string Availability { get; set; } = string.Empty;

        public string? Notes { get; set; }
    }

}