using Microsoft.EntityFrameworkCore;
using NetTopologySuite;
using NetTopologySuite.Geometries;
using Skills.Data;
using Skills.DTOs;
using Skills.Models;

namespace Skills.Services
{
    public interface IServicePostService
    {
        Task<ServicePostDto> CreatePostAsync(string artisanUserId, CreateServicePostDto dto);
        Task<ServicePostDto> UpdatePostAsync(Guid postId, string artisanUserId, UpdateServicePostDto dto);
        Task<bool> DeletePostAsync(Guid postId, string artisanUserId);
        Task<bool> DeactivatePostAsync(Guid postId, string artisanUserId);
        Task<ServicePostDto?> GetPostByIdAsync(Guid postId, string? currentUserId = null);
        Task<ArtisanProfile> GetArtisanByIdAsync(string? userId = null);
        Task<ServicePostListDto> GetPostsAsync(ServicePostFilterDto filter, string? currentUserId = null);
        Task<ServicePostListDto> GetArtisanPostsAsync(Guid artisanId, int page = 1, int pageSize = 20);
        Task<PostLikeResponseDto> ToggleLikeAsync(Guid postId, string userId);
        Task<bool> IncrementViewCountAsync(Guid postId, string? userId = null, int? dwellTimeSeconds = null);
    }

    public class ServicePostService : IServicePostService
    {
        private readonly AppDbContext _context;
        private readonly ILogger<ServicePostService> _logger;
        private readonly GeometryFactory _geometryFactory;

        public ServicePostService(
            AppDbContext context,
            ILogger<ServicePostService> logger)
        {
            _context = context;
            _logger = logger;
            _geometryFactory = new GeometryFactory(new PrecisionModel(), 4326); // WGS84
        }

        public async Task<ServicePostDto> CreatePostAsync(string artisanUserId, CreateServicePostDto dto)
        {
            // Verify user is an artisan
            var artisan = await _context.ArtisanProfiles
                .Include(a => a.User)
                .FirstOrDefaultAsync(a => a.UserId == artisanUserId);

            if (artisan == null)
            {
                throw new UnauthorizedAccessException("Only artisans can create service posts");
            }

            // Create location point
            var location = _geometryFactory.CreatePoint(new Coordinate(dto.Longitude, dto.Latitude));

            var post = new ServicePost
            {
                Id = Guid.NewGuid(),
                ArtisanId = artisan.Id,
                Title = dto.Title,
                Description = dto.Description,
                Category = dto.Category,
                Tags = dto.Tags,
                StartingPrice = dto.StartingPrice,
                PriceType = dto.PriceType,
                Currency = "NGN",
                Latitude = dto.Latitude,
                Longitude = dto.Longitude,
                Location = location,
                LocationDescription = dto.LocationDescription,
                MediaUrls = dto.MediaUrls,
                MediaTypes = dto.MediaTypes,
                ThumbnailUrl = dto.ThumbnailUrl ?? dto.MediaUrls.FirstOrDefault() ?? string.Empty,
                IsActive = true,
                IsFeatured = false,
                LikesCount = 0,
                CommentsCount = 0,
                SharesCount = 0,
                ViewsCount = 0,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.ServicePosts.Add(post);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Service post {PostId} created by artisan {ArtisanId}", post.Id, artisan.Id);

            return await GetPostByIdAsync(post.Id, artisanUserId)
                ?? throw new InvalidOperationException("Failed to retrieve created post");
        }

        public async Task<ServicePostDto> UpdatePostAsync(Guid postId, string artisanUserId, UpdateServicePostDto dto)
        {
            var post = await _context.ServicePosts
                .Include(p => p.Artisan)
                .FirstOrDefaultAsync(p => p.Id == postId);

            if (post == null)
            {
                throw new KeyNotFoundException("Service post not found");
            }

            if (post.Artisan.UserId != artisanUserId)
            {
                throw new UnauthorizedAccessException("You can only update your own posts");
            }

            // Update fields if provided
            if (dto.Title != null) post.Title = dto.Title;
            if (dto.Description != null) post.Description = dto.Description;
            if (dto.Category != null) post.Category = dto.Category;
            if (dto.Tags != null) post.Tags = dto.Tags;
            if (dto.StartingPrice.HasValue) post.StartingPrice = dto.StartingPrice;
            if (dto.PriceType != null) post.PriceType = dto.PriceType;
            if (dto.LocationDescription != null) post.LocationDescription = dto.LocationDescription;
            if (dto.MediaUrls != null) post.MediaUrls = dto.MediaUrls;
            if (dto.MediaTypes != null) post.MediaTypes = dto.MediaTypes;
            if (dto.ThumbnailUrl != null) post.ThumbnailUrl = dto.ThumbnailUrl;
            if (dto.IsActive.HasValue) post.IsActive = dto.IsActive.Value;

            // Update location if coordinates changed
            if (dto.Latitude.HasValue && dto.Longitude.HasValue)
            {
                post.Latitude = dto.Latitude.Value;
                post.Longitude = dto.Longitude.Value;
                post.Location = _geometryFactory.CreatePoint(new Coordinate(dto.Longitude.Value, dto.Latitude.Value));
            }

            post.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            _logger.LogInformation("Service post {PostId} updated", postId);

            return await GetPostByIdAsync(postId, artisanUserId)
                ?? throw new InvalidOperationException("Failed to retrieve updated post");
        }

        public async Task<bool> DeletePostAsync(Guid postId, string artisanUserId)
        {
            var post = await _context.ServicePosts
                .Include(p => p.Artisan)
                .FirstOrDefaultAsync(p => p.Id == postId);

            if (post == null)
            {
                return false;
            }

            if (post.Artisan.UserId != artisanUserId)
            {
                throw new UnauthorizedAccessException("You can only delete your own posts");
            }

            _context.ServicePosts.Remove(post);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Service post {PostId} deleted", postId);

            return true;
        }

        public async Task<bool> DeactivatePostAsync(Guid postId, string artisanUserId)
        {
            var post = await _context.ServicePosts
                .Include(p => p.Artisan)
                .FirstOrDefaultAsync(p => p.Id == postId);

            if (post == null)
            {
                return false;
            }

            if (post.Artisan.UserId != artisanUserId)
            {
                throw new UnauthorizedAccessException("You can only deactivate your own posts");
            }

            post.IsActive = false;
            post.DeactivatedAt = DateTime.UtcNow;
            post.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            _logger.LogInformation("Service post {PostId} deactivated", postId);

            return true;
        }

        public async Task<ServicePostDto?> GetPostByIdAsync(Guid postId, string? currentUserId = null)
        {
            var query = _context.ServicePosts
                .Include(p => p.Artisan)
                    .ThenInclude(a => a.User)
                .Where(p => p.Id == postId);

            var post = await query.FirstOrDefaultAsync();

            if (post == null)
            {
                return null;
            }

            bool isLiked = false;
            if (!string.IsNullOrEmpty(currentUserId))
            {
                isLiked = await _context.PostLikes
                    .AnyAsync(l => l.ServicePostId == postId && l.UserId == currentUserId);
            }

            return MapToDto(post, isLiked);
        }

        public async Task<ArtisanProfile> GetArtisanByIdAsync(string? userId = null)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return null!;
            }
            var artisan = await _context.ArtisanProfiles
                .Include(a => a.User)
                .FirstOrDefaultAsync(a => a.UserId == userId);

            return artisan!;
        }


        public async Task<ServicePostListDto> GetPostsAsync(ServicePostFilterDto filter, string? currentUserId = null)
        {
            var query = _context.ServicePosts
                .Include(p => p.Artisan)
                    .ThenInclude(a => a.User)
                .Where(p => p.IsActive)
                .AsQueryable();

            // Category filter
            if (!string.IsNullOrEmpty(filter.Category))
            {
                query = query.Where(p => p.Category == filter.Category);
            }

            // Artisan filter
            if (filter.ArtisanId.HasValue)
            {
                query = query.Where(p => p.ArtisanId == filter.ArtisanId.Value);
            }

            // Search term filter (title, description, tags)
            if (!string.IsNullOrEmpty(filter.SearchTerm))
            {
                var searchTerm = filter.SearchTerm.ToLower();
                query = query.Where(p =>
                    p.Title.ToLower().Contains(searchTerm) ||
                    p.Description.ToLower().Contains(searchTerm) ||
                    p.Tags.Any(t => t.ToLower().Contains(searchTerm)));
            }

            // Tags filter (PostgreSQL array contains)
            if (filter.Tags != null && filter.Tags.Length > 0)
            {
                query = query.Where(p => p.Tags.Any(t => filter.Tags.Contains(t)));
            }

            // Price range filter
            if (filter.MinPrice.HasValue)
            {
                query = query.Where(p => p.StartingPrice >= filter.MinPrice.Value);
            }
            if (filter.MaxPrice.HasValue)
            {
                query = query.Where(p => p.StartingPrice <= filter.MaxPrice.Value);
            }

            // Location-based filtering (if coordinates provided)
            if (filter.Latitude.HasValue && filter.Longitude.HasValue && filter.RadiusKm.HasValue)
            {
                var userLocation = _geometryFactory.CreatePoint(
                    new Coordinate(filter.Longitude.Value, filter.Latitude.Value));

                // Filter by distance (in meters, convert km to meters)
                var radiusMeters = filter.RadiusKm.Value * 1000;
                query = query.Where(p => p.Location.Distance(userLocation) <= radiusMeters);
            }

            // Sorting
            query = filter.SortBy?.ToLower() switch
            {
                "popular" => query.OrderByDescending(p => p.LikesCount)
                                  .ThenByDescending(p => p.ViewsCount),
                "nearby" when filter.Latitude.HasValue && filter.Longitude.HasValue =>
                    query.OrderBy(p => p.Location.Distance(
                        _geometryFactory.CreatePoint(new Coordinate(filter.Longitude.Value, filter.Latitude.Value)))),
                _ => query.OrderByDescending(p => p.CreatedAt) // Default: recent
            };

            // Get total count before pagination
            var totalCount = await query.CountAsync();

            // Pagination
            var posts = await query
                .Skip((filter.Page - 1) * filter.PageSize)
                .Take(filter.PageSize)
                .ToListAsync();

            // Get liked posts for current user
            HashSet<Guid> likedPostIds = new();
            if (!string.IsNullOrEmpty(currentUserId))
            {
                var postIds = posts.Select(p => p.Id).ToList();
                var likedPosts = await _context.PostLikes
                    .Where(l => l.UserId == currentUserId && postIds.Contains(l.ServicePostId))
                    .Select(l => l.ServicePostId)
                    .ToListAsync();
                likedPostIds = likedPosts.ToHashSet();
            }

            var postDtos = posts.Select(p => MapToDto(p, likedPostIds.Contains(p.Id))).ToList();

            var totalPages = (int)Math.Ceiling(totalCount / (double)filter.PageSize);

            return new ServicePostListDto
            {
                Posts = postDtos,
                TotalCount = totalCount,
                Page = filter.Page,
                PageSize = filter.PageSize,
                TotalPages = totalPages,
                HasNextPage = filter.Page < totalPages,
                HasPreviousPage = filter.Page > 1
            };
        }

        public async Task<ServicePostListDto> GetArtisanPostsAsync(Guid artisanId, int page = 1, int pageSize = 20)
        {
            var filter = new ServicePostFilterDto
            {
                ArtisanId = artisanId,
                Page = page,
                PageSize = pageSize
            };

            return await GetPostsAsync(filter);
        }

        public async Task<PostLikeResponseDto> ToggleLikeAsync(Guid postId, string userId)
        {
            var post = await _context.ServicePosts.FindAsync(postId);
            if (post == null)
            {
                throw new KeyNotFoundException("Service post not found");
            }

            var existingLike = await _context.PostLikes
                .FirstOrDefaultAsync(l => l.ServicePostId == postId && l.UserId == userId);

            bool isLiked;

            if (existingLike != null)
            {
                // Unlike
                _context.PostLikes.Remove(existingLike);
                post.LikesCount = Math.Max(0, post.LikesCount - 1);
                isLiked = false;

                _logger.LogInformation("User {UserId} unliked post {PostId}", userId, postId);
            }
            else
            {
                // Like
                var like = new PostLike
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    ServicePostId = postId,
                    CreatedAt = DateTime.UtcNow
                };

                _context.PostLikes.Add(like);
                post.LikesCount++;
                isLiked = true;

                // Track activity
                await TrackActivityAsync(userId, ActivityType.PostLiked, postId, "ServicePost", post.Category);

                _logger.LogInformation("User {UserId} liked post {PostId}", userId, postId);
            }

            await _context.SaveChangesAsync();

            return new PostLikeResponseDto
            {
                IsLiked = isLiked,
                TotalLikes = post.LikesCount
            };
        }

        public async Task<bool> IncrementViewCountAsync(Guid postId, string? userId = null, int? dwellTimeSeconds = null)
        {
            var post = await _context.ServicePosts.FindAsync(postId);
            if (post == null)
            {
                return false;
            }

            post.ViewsCount++;
            await _context.SaveChangesAsync();

            // Track activity if user is logged in
            if (!string.IsNullOrEmpty(userId))
            {
                await TrackActivityAsync(
                    userId,
                    ActivityType.PostViewed,
                    postId,
                    "ServicePost",
                    post.Category,
                    post.Latitude,
                    post.Longitude,
                    dwellTimeSeconds);
            }

            return true;
        }

        private async Task TrackActivityAsync(
            string userId,
            ActivityType activityType,
            Guid relatedEntityId,
            string relatedEntityType,
            string? category = null,
            double? latitude = null,
            double? longitude = null,
            int? dwellTimeSeconds = null)
        {
            var activity = new UserActivity
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ActivityType = activityType,
                RelatedEntityId = relatedEntityId,
                RelatedEntityType = relatedEntityType,
                Category = category,
                Latitude = latitude,
                Longitude = longitude,
                DwellTimeSeconds = dwellTimeSeconds,
                CreatedAt = DateTime.UtcNow
            };

            _context.UserActivities.Add(activity);
            // Note: SaveChanges called by parent method
        }

        private ServicePostDto MapToDto(ServicePost post, bool isLikedByCurrentUser = false, double? distanceKm = null)
        {
            return new ServicePostDto
            {
                Id = post.Id,
                ArtisanId = post.ArtisanId,
                Artisan = new ArtisanBasicInfoDto
                {
                    Id = post.Artisan.Id,
                    UserId = post.Artisan.UserId,
                    FullName = post.Artisan.User.FullName,
                    BusinessName = post.Artisan.BusinessName,
                    ProfilePhoto = post.Artisan.User.ProfilePhoto,
                    AverageRating = post.Artisan.AverageRating,
                    TotalReviews = post.Artisan.TotalReviews,
                    IsVerified = post.Artisan.IsVerified,
                    CompletedJobs = post.Artisan.CompletedJobs
                },
                Title = post.Title,
                Description = post.Description,
                Category = post.Category,
                Tags = post.Tags,
                StartingPrice = post.StartingPrice,
                PriceType = post.PriceType,
                Currency = post.Currency,
                Latitude = post.Latitude,
                Longitude = post.Longitude,
                LocationDescription = post.LocationDescription,
                DistanceKm = distanceKm,
                MediaUrls = post.MediaUrls,
                ThumbnailUrl = post.ThumbnailUrl,
                MediaTypes = post.MediaTypes,
                LikesCount = post.LikesCount,
                CommentsCount = post.CommentsCount,
                SharesCount = post.SharesCount,
                ViewsCount = post.ViewsCount,
                IsLikedByCurrentUser = isLikedByCurrentUser,
                IsActive = post.IsActive,
                IsFeatured = post.IsFeatured,
                CreatedAt = post.CreatedAt,
                UpdatedAt = post.UpdatedAt
            };
        }
    }
}