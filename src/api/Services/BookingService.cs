


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