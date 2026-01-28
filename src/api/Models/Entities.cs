using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using NetTopologySuite.Geometries;
using NetTopologySuite;


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

        [Required]
        public UserType UserType { get; set; } = UserType.Artisan;

        public UserStatus Status { get; set; } = UserStatus.New;

        [MaxLength(500)]
        public string? ProfilePhoto { get; set; }

        public bool EmailVerified { get; set; }
        public bool IsActive { get; set; } = true;

        public DateTime? LastLoginAt { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Profiles
        public virtual ArtisanProfile? ArtisanProfile { get; set; }
        public virtual UserProfile? UserProfile { get; set; }

        // Preferences & Auth
        public virtual ICollection<ServicePreference> UserPreferences { get; set; } = new List<ServicePreference>();
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();

        // Business entities
        public virtual ICollection<ServicePost> ServicePosts { get; set; } = new List<ServicePost>();
        public virtual ICollection<ServiceRequest> ServiceRequests { get; set; } = new List<ServiceRequest>();
        public virtual ICollection<PostLike> PostLikes { get; set; } = new List<PostLike>();
        public virtual ICollection<Comment> Comments { get; set; } = new List<Comment>();
        public virtual ICollection<ConversationParticipant> ConversationParticipants { get; set; } = new List<ConversationParticipant>();
        public virtual ICollection<Notification> Notifications { get; set; } = new List<Notification>();
        public virtual ICollection<UserActivity> Activities { get; set; } = new List<UserActivity>();
        public virtual ICollection<Bid> Bids { get; set; } = new List<Bid>();
        public virtual ICollection<Review> ReviewsGiven { get; set; } = new List<Review>();
        public virtual ICollection<Review> ReviewsReceived { get; set; } = new List<Review>();
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


    public class UserProfile
    {
        public Guid Id { get; set; }
        public string UserId { get; set; }

        // Location
        public string Address { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public Point Location { get; set; } = null!;

        // Preferences
        public int SearchRadiusKm { get; set; } = 50;
        public string PreferredLanguage { get; set; } = "en";
        public bool EmailNotifications { get; set; } = true;
        public bool PushNotifications { get; set; } = true;

        public DateTime UpdatedAt { get; set; }

        // Navigation
        public ApplicationUser User { get; set; }
    }

    public class ArtisanProfile
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserId { get; set; } = string.Empty;

        // Location
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public Point Location { get; set; } = Point.Empty;
        public string ServiceArea { get; set; } = string.Empty;

        [MaxLength(200)]
        public string? BusinessName { get; set; }
        public string[] Skills { get; set; } = Array.Empty<string>();
        public string[] ServiceCategories { get; set; } = Array.Empty<string>();
        public string? Bio { get; set; }
        public int? YearsOfExperience { get; set; }

        
        public decimal AverageRating { get; set; } // Changed from Rating to AverageRating
        public int TotalReviews { get; set; }
        public int CompletedJobs { get; set; }
        public decimal ResponseRate { get; set; }
        public int AverageResponseTimeMinutes { get; set; }
        public int ProfileCompletenessScore { get; set; }

        // Verification
        public bool IsVerified { get; set; } // Changed from Verified to IsVerified for consistency
        public DateTime? VerifiedAt { get; set; }
        public string[] CertificationUrls { get; set; } = Array.Empty<string>();

        // Availability
        public bool IsAvailable { get; set; } = true;
        public DateTime? AvailableFrom { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Navigation
        public virtual ApplicationUser User { get; set; } = null!;

        public virtual ICollection<ServicePost> ServicePosts { get; set; } = new List<ServicePost>();

        public virtual ICollection<Service> Services { get; set; } = new List<Service>();
        public virtual ICollection<PortfolioItem> Portfolio { get; set; } = new List<PortfolioItem>();
    }
    
    
    public class PortfolioItem
    {
        public Guid Id { get; set; }
        public Guid ArtisanProfileId { get; set; }

        public string Title { get; set; }
        public string Description { get; set; }
        public string[] MediaUrls { get; set; }
        public string ThumbnailUrl { get; set; }
        public string Category { get; set; }

        public int DisplayOrder { get; set; }
        public bool IsFeatured { get; set; }

        public DateTime CreatedAt { get; set; }

        // Navigation
        public ArtisanProfile ArtisanProfile { get; set; }
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
        public Guid Id { get; set; }
        public Guid ServiceId { get; set; }
        public Guid ServiceRequestId { get; set; }
        public Guid AcceptedBidId { get; set; }
        public string CustomerId { get; set; } = string.Empty;
        public string ArtisanId { get; set; } = string.Empty;

        public DateTime BookingDate { get; set; }
        public decimal AgreedPrice { get; set; }
        public string Currency { get; set; } = "NGN";
        public DateTime StartDate { get; set; }
        public DateTime? CompletionDate { get; set; }

        public BookingStatus Status { get; set; } = BookingStatus.Pending;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? CompletedAt { get; set; }
        public DateTime? CancelledAt { get; set; }
        public string? CancellationReason { get; set; }

        // Navigation
        public virtual ServiceRequest ServiceRequest { get; set; } = null!;
        public virtual Bid AcceptedBid { get; set; } = null!;
        public virtual ApplicationUser Customer { get; set; } = null!;
        public virtual ApplicationUser Artisan { get; set; } = null!;
        public virtual Conversation? Conversation { get; set; }
        public virtual Review? Review { get; set; }
        public virtual Service Service { get; set; } = null!;
    }

    public enum BookingStatus
    {
        Pending = 0,
        Accepted = 1,
        Rejected = 2,
        CancelledByUser = 3,
        CancelledByArtisan = 4,
        Expired = 5,
        InProgress = 6,
        Completed = 7,
        NoShow = 8,
        Failed = 9,
        Refunded = 10,
        Disputed = 11
    }

    public class Review
    {
        public Guid Id { get; set; }
        public Guid BookingId { get; set; }
        public string ReviewerId { get; set; } // Customer reviewing artisan
        public string ArtisanId { get; set; }

        // Rating (1-5 stars)
        public int OverallRating { get; set; }
        public int? QualityRating { get; set; }
        public int? ProfessionalismRating { get; set; }
        public int? TimelinessRating { get; set; }
        public int? CommunicationRating { get; set; }

        // Review content
        public string Comment { get; set; }
        public string[] PhotoUrls { get; set; }

        // Engagement
        public int HelpfulCount { get; set; }

        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }

        // Response from artisan
        public string ArtisanResponse { get; set; }
        public DateTime? RespondedAt { get; set; }

        // Navigation
        public Booking Booking { get; set; }
        public ApplicationUser Reviewer { get; set; }
        public ApplicationUser Artisan { get; set; }
    }

    public class Conversation
    {
        public Guid Id { get; set; }
        public Guid? ServicePostId { get; set; } // Context: initiated from post
        public Guid? BookingId { get; set; } // Context: linked to booking

        public ConversationType Type { get; set; } // "Inquiry", "Booking", "Support"
        public DateTime CreatedAt { get; set; }
        public DateTime LastMessageAt { get; set; }
        public bool IsArchived { get; set; }

        // Navigation
        public ServicePost ServicePost { get; set; }
        public Booking Booking { get; set; }
        public ICollection<ConversationParticipant> Participants { get; set; }
        public ICollection<Message> Messages { get; set; }
    }

    public enum ConversationType
    {
        Inquiry = 1,      // General inquiry about service
        Booking = 2,      // Related to active booking
        Support = 3       // Customer support
    }

    public class ConversationParticipant
    {
        public Guid Id { get; set; }
        public Guid ConversationId { get; set; }
        public string UserId { get; set; }

        public int UnreadCount { get; set; }
        public DateTime? LastReadAt { get; set; }
        public DateTime JoinedAt { get; set; }
        public DateTime? LeftAt { get; set; }

        // Navigation
        public Conversation Conversation { get; set; }
        public ApplicationUser User { get; set; }
    }

    public class Message
    {
        public Guid Id { get; set; }
        public Guid ConversationId { get; set; }
        public string SenderId { get; set; }

        public string Content { get; set; }
        public MessageType Type { get; set; } // "Text", "Image", "File", "System"
        public string[] AttachmentUrls { get; set; }

        // Delivery tracking
        public DateTime CreatedAt { get; set; }
        public DateTime? DeliveredAt { get; set; }
        public bool IsRead { get; set; }
        public DateTime? ReadAt { get; set; }

        public bool IsEdited { get; set; }
        public bool IsDeleted { get; set; }

        // Navigation
        public Conversation Conversation { get; set; }
        public ApplicationUser Sender { get; set; }
    }

    public enum MessageType
    {
        Text = 1,
        Image = 2,
        File = 3,
        System = 4  // "Booking confirmed", "Payment received", etc.
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

    public class ServicePost
    {
        public Guid Id { get; set; }
        public Guid ArtisanId { get; set; }

        // Content
        public string Title { get; set; }
        public string Description { get; set; }
        public string Category { get; set; }
        public string[] Tags { get; set; }

        // Pricing
        public decimal? StartingPrice { get; set; }
        public string PriceType { get; set; } // "Fixed", "Hourly", "Negotiable"
        public string Currency { get; set; } = "NGN";

        // Location
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public Point Location { get; set; }
        public string LocationDescription { get; set; }

        // Media
        public string[] MediaUrls { get; set; }
        public string ThumbnailUrl { get; set; }
        public string[] MediaTypes { get; set; } // "image", "video"

        // Engagement metrics
        public int LikesCount { get; set; }
        public int CommentsCount { get; set; }
        public int SharesCount { get; set; }
        public int ViewsCount { get; set; }

        // Metadata
        public bool IsActive { get; set; } = true;
        public bool IsFeatured { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public DateTime? DeactivatedAt { get; set; }

        // Navigation
        public ArtisanProfile Artisan { get; set; }
        public ICollection<PostLike> Likes { get; set; }
        public ICollection<Comment> Comments { get; set; }
        public ICollection<PostShare> Shares { get; set; }
        public ICollection<Conversation> RelatedConversations { get; set; }
    }

    public class PostLike
    {
        public Guid Id { get; set; }
        public string UserId { get; set; }
        public Guid ServicePostId { get; set; }
        public DateTime CreatedAt { get; set; }

        // Navigation
        public ApplicationUser User { get; set; }
        public ServicePost ServicePost { get; set; }
    }

    public class Comment
    {
        public Guid Id { get; set; }
        public string UserId { get; set; }
        public Guid ServicePostId { get; set; }
        public Guid? ParentCommentId { get; set; } // For replies

        public string Content { get; set; }
        public int LikesCount { get; set; }

        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public bool IsEdited { get; set; }
        public bool IsDeleted { get; set; }

        // Navigation
        public ApplicationUser User { get; set; }
        public ServicePost ServicePost { get; set; }
        public Comment ParentComment { get; set; }
        public ICollection<Comment> Replies { get; set; }
    }

    public class PostShare
    {
        public Guid Id { get; set; }
        public string UserId { get; set; }
        public Guid ServicePostId { get; set; }
        public string ShareMethod { get; set; } // "WhatsApp", "Twitter", "Copy", etc.
        public DateTime CreatedAt { get; set; }

        // Navigation
        public ApplicationUser User { get; set; }
        public ServicePost ServicePost { get; set; }
    }

    public class ServiceRequest
    {
        public Guid Id { get; set; }
        public string UserId { get; set; }

        // Request details
        public string Title { get; set; }
        public string Description { get; set; }
        public string Category { get; set; }
        public string[] RequiredSkills { get; set; }

        // Budget & Timeline
        public decimal? BudgetMin { get; set; }
        public decimal? BudgetMax { get; set; }
        public string Currency { get; set; } = "NGN";
        public DateTime? NeededBy { get; set; }
        public string Urgency { get; set; } // "Flexible", "Within a week", "Urgent"

        // Location
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public Point Location { get; set; }
        public string LocationDescription { get; set; }

        // Media attachments
        public string[] AttachmentUrls { get; set; }

        // Status
        public RequestStatus Status { get; set; }
        public int BidsCount { get; set; }
        public int ViewsCount { get; set; }

        public DateTime CreatedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }

        // Navigation
        public ApplicationUser User { get; set; }
        public ICollection<Bid> Bids { get; set; }
        public Booking Booking { get; set; } // One booking per request
    }

    public enum RequestStatus
    {
        Open = 1,
        BiddingClosed = 2,
        Awarded = 3,
        InProgress = 4,
        Completed = 5,
        Cancelled = 6,
        Expired = 7
    }

    public class Bid
    {
        public Guid Id { get; set; }
        public Guid ServiceRequestId { get; set; }
        public string ArtisanId { get; set; }

        // Bid details
        public decimal ProposedPrice { get; set; }
        public string Currency { get; set; } = "NGN";
        public string CoverLetter { get; set; }
        public int EstimatedDurationDays { get; set; }
        public DateTime CanStartFrom { get; set; }

        // Bid metrics (for ranking)
        public decimal BidRankScore { get; set; } // Calculated by algorithm

        // Status
        public BidStatus Status { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? AcceptedAt { get; set; }
        public DateTime? RejectedAt { get; set; }

        // Navigation
        public ServiceRequest ServiceRequest { get; set; }
        public ApplicationUser Artisan { get; set; }
    }

    public enum BidStatus
    {
        Pending = 1,
        Accepted = 2,
        Rejected = 3,
        Withdrawn = 4
    }


    public class Notification
    {
        public Guid Id { get; set; }
        public string UserId { get; set; }

        public NotificationType Type { get; set; }
        public string Title { get; set; }
        public string Message { get; set; }

        // Context linking
        public Guid? RelatedEntityId { get; set; } // PostId, BidId, MessageId, etc.
        public string RelatedEntityType { get; set; } // "ServicePost", "Bid", "Message"
        public string ActionUrl { get; set; } // Deep link

        // Metadata
        public string IconUrl { get; set; }
        public NotificationPriority Priority { get; set; }

        // Status
        public bool IsRead { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? ReadAt { get; set; }
        public DateTime? DeliveredAt { get; set; }

        // Delivery channels
        public bool PushSent { get; set; }
        public bool EmailSent { get; set; }

        // Navigation
        public ApplicationUser User { get; set; }
    }

    public enum NotificationType
    {
        // Post interactions
        PostLiked = 1,
        PostCommented = 2,
        PostShared = 3,

        // Service requests
        NewRequestMatch = 10,
        NewBidReceived = 11,
        BidAccepted = 12,
        BidRejected = 13,

        // Messaging
        NewMessage = 20,
        NewConversation = 21,

        // Booking
        BookingConfirmed = 30,
        BookingStarted = 31,
        BookingCompleted = 32,
        BookingCancelled = 33,

        // Reviews
        NewReview = 40,

        // Profile
        NewFollower = 50,
        ProfileVerified = 51,

        // System
        SystemAnnouncement = 100
    }

    public enum NotificationPriority
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Urgent = 4
    }

    public class UserActivity
    {
        public Guid Id { get; set; }
        public string UserId { get; set; } = string.Empty; // FIXED: was "sting"

        public ActivityType ActivityType { get; set; }
        public Guid? RelatedEntityId { get; set; }
        public string? RelatedEntityType { get; set; }

        // Metadata
        public string? Category { get; set; }
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }
        public int? DwellTimeSeconds { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Navigation
        public virtual ApplicationUser User { get; set; } = null!;
    }

    public enum ActivityType
    {
        PostViewed = 1,
        PostLiked = 2,
        PostCommented = 3,
        PostShared = 4,
        SearchPerformed = 5,
        ArtisanProfileViewed = 6,
        ArtisanContacted = 7,
        RequestCreated = 8,
        BidSubmitted = 9,
        BidAccepted = 10
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