using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Skills.DTOs;
using Skills.Services;
using System.Security.Claims;

namespace Skills.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ServicePostsController : ControllerBase
    {
        private readonly IServicePostService _servicePostService;
        private readonly ILogger<ServicePostsController> _logger;

        public ServicePostsController(
            IServicePostService servicePostService,
            ILogger<ServicePostsController> logger)
        {
            _servicePostService = servicePostService;
            _logger = logger;
        }

        private string GetCurrentUserId()
        {
            return User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? throw new UnauthorizedAccessException("User ID not found in token");
        }

        /// <summary>
        /// Create a new service post (Artisans only)
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<ServicePostDto>> CreatePost([FromBody] CreateServicePostDto dto)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _servicePostService.CreatePostAsync(userId, dto);
                return CreatedAtAction(nameof(GetPost), new { id = result.Id }, result);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Forbid(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating service post");
                return StatusCode(500, new { message = "An error occurred while creating the post" });
            }
        }

        /// <summary>
        /// Update an existing service post
        /// </summary>
        [HttpPut("{id}")]
        public async Task<ActionResult<ServicePostDto>> UpdatePost(Guid id, [FromBody] UpdateServicePostDto dto)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _servicePostService.UpdatePostAsync(id, userId, dto);
                return Ok(result);
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(new { message = ex.Message });
            }
            catch (UnauthorizedAccessException ex)
            {
                return Forbid(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating service post {PostId}", id);
                return StatusCode(500, new { message = "An error occurred while updating the post" });
            }
        }

        /// <summary>
        /// Delete a service post (hard delete)
        /// </summary>
        [HttpDelete("{id}")]
        public async Task<ActionResult> DeletePost(Guid id)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _servicePostService.DeletePostAsync(id, userId);

                if (!result)
                {
                    return NotFound(new { message = "Post not found" });
                }

                return NoContent();
            }
            catch (UnauthorizedAccessException ex)
            {
                return Forbid(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting service post {PostId}", id);
                return StatusCode(500, new { message = "An error occurred while deleting the post" });
            }
        }

        /// <summary>
        /// Deactivate a service post (soft delete)
        /// </summary>
        [HttpPatch("{id}/deactivate")]
        public async Task<ActionResult> DeactivatePost(Guid id)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _servicePostService.DeactivatePostAsync(id, userId);

                if (!result)
                {
                    return NotFound(new { message = "Post not found" });
                }

                return Ok(new { message = "Post deactivated successfully" });
            }
            catch (UnauthorizedAccessException ex)
            {
                return Forbid(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deactivating service post {PostId}", id);
                return StatusCode(500, new { message = "An error occurred while deactivating the post" });
            }
        }

        /// <summary>
        /// Get a single service post by ID
        /// </summary>
        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<ServicePostDto>> GetPost(Guid id)
        {
            try
            {
                var userId = User.Identity?.IsAuthenticated == true ? GetCurrentUserId() : null;
                var result = await _servicePostService.GetPostByIdAsync(id, userId);

                if (result == null)
                {
                    return NotFound(new { message = "Post not found" });
                }

                // Increment view count (fire and forget)
                _ = Task.Run(() => _servicePostService.IncrementViewCountAsync(id, userId));

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving service post {PostId}", id);
                return StatusCode(500, new { message = "An error occurred while retrieving the post" });
            }
        }

        /// <summary>
        /// Get service posts with filtering, searching, and pagination
        /// </summary>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<ServicePostListDto>> GetPosts([FromQuery] ServicePostFilterDto filter)
        {
            try
            {
                var userId = User.Identity?.IsAuthenticated == true ? GetCurrentUserId() : null;
                var result = await _servicePostService.GetPostsAsync(filter, userId);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving service posts");
                return StatusCode(500, new { message = "An error occurred while retrieving posts" });
            }
        }

        /// <summary>
        /// Get all posts by a specific artisan
        /// </summary>
        [HttpGet("artisan/{artisanId}")]
        [AllowAnonymous]
        public async Task<ActionResult<ServicePostListDto>> GetArtisanPosts(
            Guid artisanId,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20)
        {
            try
            {
                var result = await _servicePostService.GetArtisanPostsAsync(artisanId, page, pageSize);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving artisan posts for {ArtisanId}", artisanId);
                return StatusCode(500, new { message = "An error occurred while retrieving artisan posts" });
            }
        }

        /// <summary>
        /// Like or unlike a service post
        /// </summary>
        [HttpPost("{id}/like")]
        public async Task<ActionResult<PostLikeResponseDto>> ToggleLike(Guid id)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _servicePostService.ToggleLikeAsync(id, userId);
                return Ok(result);
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error toggling like for post {PostId}", id);
                return StatusCode(500, new { message = "An error occurred while processing your request" });
            }
        }

        /// <summary>
        /// Manually increment view count (optional - usually done automatically)
        /// </summary>
        [HttpPost("{id}/view")]
        [AllowAnonymous]
        public async Task<ActionResult> IncrementView(Guid id, [FromBody] IncrementViewDto? dto = null)
        {
            try
            {
                var userId = User.Identity?.IsAuthenticated == true ? GetCurrentUserId() : null;
                var result = await _servicePostService.IncrementViewCountAsync(
                    id,
                    userId,
                    dto?.DwellTimeSeconds);

                if (!result)
                {
                    return NotFound(new { message = "Post not found" });
                }

                return Ok(new { message = "View count incremented" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error incrementing view count for post {PostId}", id);
                return StatusCode(500, new { message = "An error occurred while processing your request" });
            }
        }

        /// <summary>
        /// Get my posts (current artisan)
        /// </summary>
        [HttpGet("my-posts")]
        public async Task<ActionResult<ServicePostListDto>> GetMyPosts(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20)
        {
            try
            {
                var userId = GetCurrentUserId();

                // Get artisan profile ID
                //var artisan = await _context.ArtisanProfiles
                //    .FirstOrDefaultAsync(a => a.UserId == userId);
                var artisan = await _servicePostService.GetArtisanByIdAsync(userId);


                if (artisan == null)
                {
                    return Forbid("Only artisans can access this endpoint");
                }

                var result = await _servicePostService.GetArtisanPostsAsync(artisan.Id, page, pageSize);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user's posts");
                return StatusCode(500, new { message = "An error occurred while retrieving your posts" });
            }
        }
    }
}