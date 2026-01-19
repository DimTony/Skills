using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;


namespace Skills.Models
{
    public class ApplicationUser : IdentityUser
    {


        [Required, MaxLength(100)]
        public string FirstName { get; set; } = string.Empty;

        [Required, MaxLength(100)]
        public string LastName { get; set; } = string.Empty;

        [NotMapped]
        public string FullName => $"{FirstName} {LastName}";

        [Required, MaxLength(20)]
        public UserType UserType { get; set; } = UserType.Artisan; // "user" or "artisan"

        public UserStatus Status { get; set; }

        //[Required, MaxLength(20)]
        //public string PhoneNumber { get; set; } = string.Empty;

        [MaxLength(500)]
        public string? ProfilePhoto { get; set; }

        public bool EmailVerified { get; set; }
        public bool IsActive { get; set; } = true;

        public DateTime? LastLoginAt { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        public virtual ArtisanProfile? ArtisanProfile { get; set; }
        public virtual ICollection<ServicePreference> UserPreferences { get; set; } = new List<ServicePreference>();
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }

    public enum UserType
    {
        User = 0,
        Artisan = 1,
        Admin = 2
    }

    public enum UserStatus
    {
        Deleted = 0,
        Inactive = 1,
        Locked = 2,
        Suspended = 3,
        Active = 4,
        Pending = 5,
        New = 6,
    }

    public class ApplicationRole : IdentityRole
    {
        public string Description { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class ArtisanProfile
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserId { get; set; } = string.Empty;

        [MaxLength(200)]
        public string? BusinessName { get; set; }

        public string? Bio { get; set; }
        public int? YearsOfExperience { get; set; }
        public decimal Rating { get; set; }
        public int TotalReviews { get; set; }
        public bool Verified { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        public virtual ApplicationUser User { get; set; } = null!;
        public virtual ICollection<Service> Services { get; set; } = new List<Service>();
    }

    public class Service
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid ArtisanId { get; set; }

        [Required, MaxLength(200)]
        public string Name { get; set; } = string.Empty;

        [Required, MaxLength(100)]
        public string Category { get; set; } = string.Empty;

        public string? Description { get; set; }

        [Required, MaxLength(20)]
        public PricingModel PricingModel { get; set; } = PricingModel.Fixed; // "fixed", "hourly", "quote"

        public decimal? MinPrice { get; set; }
        public decimal? MaxPrice { get; set; }
        public string? Availability { get; set; } // JSON string
        public string? Notes { get; set; }
        public bool IsActive { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        public virtual ArtisanProfile ArtisanProfile { get; set; } = null!;
    }

    public class ServicePreference
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserId { get; set; } = string.Empty;

        [Required, MaxLength(100)]
        public string ServiceCategory { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public virtual ApplicationUser User { get; set; } = null!;
    }

    public enum PricingModel
    {
        Fixed = 0,
        Hourly = 1,
        Quote = 2
    }

    public class RefreshToken
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserId { get; set; } = string.Empty;

        [Required, MaxLength(255)]
        public string TokenHash { get; set; } = string.Empty;

        [MaxLength(500)]
        public string? DeviceInfo { get; set; }

        [MaxLength(45)]
        public string? IpAddress { get; set; }

        public DateTime ExpiresAt { get; set; }
        public bool Revoked { get; set; }
        public DateTime? RevokedAt { get; set; }

        [MaxLength(200)]
        public string? RevokedReason { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public virtual ApplicationUser User { get; set; } = null!;
    }

    public class Booking
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public Guid ServiceId { get; set; }
        public DateTime BookingDate { get; set; }
        public string Status { get; set; } = "Pending";
        public ApplicationUser? User { get; set; }
        public Service? Service { get; set; }
    }

    public enum BookingStatus
    {
        // Initial
        Pending = 0,          // User created booking, waiting for artisan response

        // Artisan actions
        Accepted = 1,         // Artisan accepted the booking
        Rejected = 2,         // Artisan rejected the booking

        // Pre-service
        CancelledByUser = 3,  // User cancelled before service
        CancelledByArtisan = 4, // Artisan cancelled before service
        Expired = 5,          // No response within allowed time

        // In progress
        InProgress = 6,       // Artisan started the job

        // Completion
        Completed = 7,        // Service completed successfully

        // Payment / issues
        NoShow = 8,           // User didn’t show up
        Failed = 9,           // Service could not be completed
        Refunded = 10,        // Payment refunded

        // Post-completion
        Disputed = 11         // User raised a dispute
    }

    public class PasswordResetToken
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserId { get; set; } = string.Empty;
        public string TokenHash { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public bool Used { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public virtual ApplicationUser User { get; set; } = null!;
    }

    public class EmailVerificationToken
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string TokenHash { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public bool Used { get; set; }
        public DateTime? UsedAt { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public virtual ApplicationUser User { get; set; } = null!;
    }

    public class AuditLog
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string? UserId { get; set; }
        public string Action { get; set; } = string.Empty; // "Login", "Logout", "PasswordChange", etc.
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public bool Success { get; set; }
        public string? Details { get; set; } // JSON
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }


}