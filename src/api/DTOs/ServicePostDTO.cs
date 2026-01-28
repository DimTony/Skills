using System.ComponentModel.DataAnnotations;

namespace Skills.DTOs
{   
    public class CreateServicePostDto
    {
        [Required, MaxLength(200)]
        public string Title { get; set; } = string.Empty;

        [Required, MaxLength(2000)]
        public string Description { get; set; } = string.Empty;

        [Required, MaxLength(100)]
        public string Category { get; set; } = string.Empty;

        public string[] Tags { get; set; } = Array.Empty<string>();

        // Pricing
        public decimal? StartingPrice { get; set; }

        [Required]
        public string PriceType { get; set; } = "Negotiable"; // "Fixed", "Hourly", "Negotiable"

        // Location
        [Required]
        public double Latitude { get; set; }

        [Required]
        public double Longitude { get; set; }

        [Required, MaxLength(200)]
        public string LocationDescription { get; set; } = string.Empty;

        // Media URLs (uploaded separately)
        public string[] MediaUrls { get; set; } = Array.Empty<string>();
        public string[] MediaTypes { get; set; } = Array.Empty<string>();
        public string? ThumbnailUrl { get; set; }
    }

    public class UpdateServicePostDto
    {
        [MaxLength(200)]
        public string? Title { get; set; }

        [MaxLength(2000)]
        public string? Description { get; set; }

        [MaxLength(100)]
        public string? Category { get; set; }

        public string[]? Tags { get; set; }

        public decimal? StartingPrice { get; set; }
        public string? PriceType { get; set; }

        public double? Latitude { get; set; }
        public double? Longitude { get; set; }

        [MaxLength(200)]
        public string? LocationDescription { get; set; }

        public string[]? MediaUrls { get; set; }
        public string[]? MediaTypes { get; set; }
        public string? ThumbnailUrl { get; set; }

        public bool? IsActive { get; set; }
    }

    public class ServicePostFilterDto
    {
        public string? Category { get; set; }
        public string? SearchTerm { get; set; }
        public string[]? Tags { get; set; }

        // Location-based filtering
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }
        public double? RadiusKm { get; set; } = 50; // Default 50km

        // Price filtering
        public decimal? MinPrice { get; set; }
        public decimal? MaxPrice { get; set; }

        // Sorting
        public string SortBy { get; set; } = "recent"; // "recent", "popular", "nearby"

        // Pagination
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 20;

        // Filter by specific artisan
        public Guid? ArtisanId { get; set; }
    }

    public class ServicePostDto
    {
        public Guid Id { get; set; }
        public Guid ArtisanId { get; set; }

        // Artisan info
        public ArtisanBasicInfoDto Artisan { get; set; } = null!;

        // Content
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string[] Tags { get; set; } = Array.Empty<string>();

        // Pricing
        public decimal? StartingPrice { get; set; }
        public string PriceType { get; set; } = string.Empty;
        public string Currency { get; set; } = "NGN";

        // Location
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public string LocationDescription { get; set; } = string.Empty;
        public double? DistanceKm { get; set; } // Calculated if user location provided

        // Media
        public string[] MediaUrls { get; set; } = Array.Empty<string>();
        public string ThumbnailUrl { get; set; } = string.Empty;
        public string[] MediaTypes { get; set; } = Array.Empty<string>();

        // Engagement
        public int LikesCount { get; set; }
        public int CommentsCount { get; set; }
        public int SharesCount { get; set; }
        public int ViewsCount { get; set; }

        // User engagement status
        public bool IsLikedByCurrentUser { get; set; }

        // Status
        public bool IsActive { get; set; }
        public bool IsFeatured { get; set; }

        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    public class ServicePostListDto
    {
        public List<ServicePostDto> Posts { get; set; } = new();
        public int TotalCount { get; set; }
        public int Page { get; set; }
        public int PageSize { get; set; }
        public int TotalPages { get; set; }
        public bool HasNextPage { get; set; }
        public bool HasPreviousPage { get; set; }
    }

    public class ArtisanBasicInfoDto
    {
        public Guid Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string? BusinessName { get; set; }
        public string? ProfilePhoto { get; set; }
        public decimal AverageRating { get; set; }
        public int TotalReviews { get; set; }
        public bool IsVerified { get; set; }
        public int CompletedJobs { get; set; }
    }

    public class LikePostDto
    {
        public Guid PostId { get; set; }
    }

    public class PostLikeResponseDto
    {
        public bool IsLiked { get; set; }
        public int TotalLikes { get; set; }
    }

    public class IncrementViewDto
    {
        public Guid PostId { get; set; }
        public int? DwellTimeSeconds { get; set; }
    }
}