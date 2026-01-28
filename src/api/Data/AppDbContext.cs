using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Skills.Models;

namespace Skills.Data
{
	public class AppDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
	{
		public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
		{
		}

		public DbSet<ArtisanProfile> ArtisanProfiles { get; set; }
		public DbSet<Service> Services { get; set; }
		public DbSet<RefreshToken> RefreshTokens { get; set; }
		
		public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }
		public DbSet<EmailVerificationToken> EmailVerificationTokens { get; set; }
		public DbSet<ServicePreference> ServicePreferences { get; set; }
		public DbSet<AuditLog> AuditLogs { get; set; }

        public override DbSet<ApplicationUser> Users { get; set; }
        public DbSet<UserProfile> UserProfiles { get; set; }
        
        public DbSet<ServicePost> ServicePosts { get; set; }
        public DbSet<PostLike> PostLikes { get; set; }
        public DbSet<Comment> Comments { get; set; }
        public DbSet<PostShare> PostShares { get; set; }
        public DbSet<ServiceRequest> ServiceRequests { get; set; }
        public DbSet<Bid> Bids { get; set; }
        public DbSet<Booking> Bookings { get; set; }
        public DbSet<Conversation> Conversations { get; set; }
        public DbSet<ConversationParticipant> ConversationParticipants { get; set; }
        public DbSet<Message> Messages { get; set; }
        public DbSet<Review> Reviews { get; set; }
        public DbSet<Notification> Notifications { get; set; }
        public DbSet<UserActivity> UserActivities { get; set; }
        public DbSet<PortfolioItem> PortfolioItems { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
		{
			base.OnModelCreating(builder);

			// ApplicationUser configuration
			builder.Entity<ApplicationUser>(entity =>
			{
				entity.Property(e => e.FirstName).IsRequired().HasMaxLength(100);
				entity.Property(e => e.LastName).IsRequired().HasMaxLength(100);
				entity.Property(e => e.PhoneNumber).IsRequired().HasMaxLength(20);
				entity.Property(e => e.ProfilePhoto).HasMaxLength(500);
				entity.Property(e => e.UserType).HasConversion<int>();
				entity.Property(e => e.Status).HasConversion<int>();

				entity.HasIndex(e => e.Email).IsUnique();
				entity.HasIndex(e => e.PhoneNumber).IsUnique();
				entity.HasIndex(e => e.UserType);
				entity.HasIndex(e => e.Status);

                entity.HasOne(e => e.UserProfile)
    .WithOne(e => e.User)
    .HasForeignKey<UserProfile>(e => e.UserId)
    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(e => e.ArtisanProfile)
                    .WithOne(e => e.User)
                    .HasForeignKey<ArtisanProfile>(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<UserProfile>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.UserId).IsUnique();

                
                //entity.HasIndex(e => e.Location)
                //    .HasMethod("GIST");

                // Regular B-tree composite index for filtering
                //entity.HasIndex(e => new { e.IsAvailable, e.AverageRating, e.IsVerified });
            });

            // ArtisanProfile configuration
            builder.Entity<ArtisanProfile>(entity =>
			{
				entity.HasKey(e => e.Id);
				entity.Property(e => e.BusinessName).HasMaxLength(200);
                entity.Property(e => e.AverageRating).HasColumnType("decimal(3,2)");
                entity.HasIndex(e => e.AverageRating);

                entity.HasOne(e => e.User)
					.WithOne(u => u.ArtisanProfile)
					.HasForeignKey<ArtisanProfile>(e => e.UserId)
					.OnDelete(DeleteBehavior.Cascade);

				entity.HasIndex(e => e.UserId).IsUnique();
				entity.HasIndex(e => e.AverageRating);
                entity.HasIndex(e => e.IsVerified);

                //entity.HasIndex(e => e.Location)
                //    .HasMethod("GIST");

                
                entity.HasIndex(e => new { e.IsAvailable, e.AverageRating, e.IsVerified });

                
                entity.HasIndex(e => e.Skills)
                    .HasMethod("GIN"); 

                entity.HasIndex(e => e.ServiceCategories)
    .HasMethod("GIN");

                
            });


			// RefreshToken configuration
			builder.Entity<RefreshToken>(entity =>
			{
				entity.HasKey(e => e.Id);
				entity.Property(e => e.TokenHash).IsRequired().HasMaxLength(255);
				entity.Property(e => e.DeviceInfo).HasMaxLength(500);
				entity.Property(e => e.IpAddress).HasMaxLength(45);
				entity.Property(e => e.RevokedReason).HasMaxLength(200);

				entity.HasOne(e => e.User)
					.WithMany(u => u.RefreshTokens)
					.HasForeignKey(e => e.UserId)
					.OnDelete(DeleteBehavior.Cascade);

				entity.HasIndex(e => e.TokenHash);
				entity.HasIndex(e => e.UserId);
				entity.HasIndex(e => e.ExpiresAt);
			});

	
			// PasswordResetToken configuration
			builder.Entity<PasswordResetToken>(entity =>
			{
				entity.HasKey(e => e.Id);
				entity.Property(e => e.TokenHash).IsRequired();

				entity.HasOne(e => e.User)
					.WithMany()
					.HasForeignKey(e => e.UserId)
					.OnDelete(DeleteBehavior.Cascade);

				entity.HasIndex(e => e.TokenHash);
				entity.HasIndex(e => e.UserId);
				entity.HasIndex(e => e.ExpiresAt);
			});

			builder.Entity<ApplicationRole>(entity =>
			{
				entity.Property(e => e.Description).HasMaxLength(200);
			});

			// EmailVerificationToken configuration
			builder.Entity<EmailVerificationToken>(entity =>
			{
				entity.HasKey(e => e.Id);

				entity.Property(e => e.TokenHash).IsRequired();
				entity.Property(e => e.Email).IsRequired(); // Regular string property, NOT a foreign key
				entity.Property(e => e.UserId).IsRequired();

				// Only UserId should be a foreign key
				entity.HasOne(e => e.User)
					.WithMany()
					.HasForeignKey(e => e.UserId) // ← Only this is the foreign key
					.OnDelete(DeleteBehavior.Cascade);

				entity.HasIndex(e => e.TokenHash);
				entity.HasIndex(e => e.UserId);
				entity.HasIndex(e => e.Email); // Regular index, not a foreign key
				entity.HasIndex(e => e.ExpiresAt);
			});


            // Service configuration
            builder.Entity<Service>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
                entity.Property(e => e.Category).IsRequired().HasMaxLength(100);
                entity.Property(e => e.PricingModel).HasConversion<int>();
                entity.Property(e => e.MinPrice).HasColumnType("decimal(18,2)");
                entity.Property(e => e.MaxPrice).HasColumnType("decimal(18,2)");

                entity.HasOne(e => e.ArtisanProfile)
                    .WithMany(a => a.Services)
                    .HasForeignKey(e => e.ArtisanId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasIndex(e => e.ArtisanId);
                entity.HasIndex(e => e.Category);
                entity.HasIndex(e => e.IsActive);
            });

            builder.Entity<ServicePost>(entity =>
            {
                entity.HasKey(e => e.Id);

                // Primary indexes for feed queries
                entity.HasIndex(e => new { e.IsActive, e.CreatedAt });
                entity.HasIndex(e => new { e.ArtisanId, e.CreatedAt });
                entity.HasIndex(e => new { e.Category, e.CreatedAt });

                // Geospatial index for location-based feed
                //entity.HasIndex(e => new { e.Location, e.IsActive })
                //    .HasMethod("GIST");

                // Full-text search indexes
                entity.HasIndex(e => e.Tags).HasMethod("GIN");

                entity.HasOne(e => e.Artisan)
                    .WithMany(e => e.ServicePosts)
                    .HasForeignKey(e => e.ArtisanId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Booking configuration
            builder.Entity<Booking>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.HasOne(e => e.Customer)
                    .WithMany()
                    .HasForeignKey(e => e.CustomerId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(e => e.Artisan)
    .WithMany()
    .HasForeignKey(e => e.ArtisanId)
    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(e => e.Service)
                    .WithMany()
                    .HasForeignKey(e => e.ServiceId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(e => e.ServiceRequest)
    .WithOne(e => e.Booking)
    .HasForeignKey<Booking>(e => e.ServiceRequestId)
    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(e => e.AcceptedBid)
    .WithMany()
    .HasForeignKey(e => e.AcceptedBidId)
    .OnDelete(DeleteBehavior.Restrict);

                entity.HasIndex(e => e.CustomerId);
                entity.HasIndex(e => e.ServiceId);
                entity.HasIndex(e => e.Status);
                entity.HasIndex(e => e.BookingDate);

                entity.HasIndex(e => new { e.CustomerId, e.Status, e.CreatedAt });
                entity.HasIndex(e => new { e.ArtisanId, e.Status, e.CreatedAt });
                entity.HasIndex(e => e.ServiceRequestId).IsUnique();
                entity.HasIndex(e => e.AcceptedBidId).IsUnique();

            });

            builder.Entity<PostLike>(entity =>
            {
                entity.HasKey(e => e.Id);

                // Unique constraint: one like per user per post
                entity.HasIndex(e => new { e.UserId, e.ServicePostId }).IsUnique();
                entity.HasIndex(e => new { e.ServicePostId, e.CreatedAt });

                entity.HasOne(e => e.User)
                    .WithMany(e => e.PostLikes)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(e => e.ServicePost)
                    .WithMany(e => e.Likes)
                    .HasForeignKey(e => e.ServicePostId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<Comment>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => new { e.ServicePostId, e.CreatedAt });
                entity.HasIndex(e => e.ParentCommentId);

                entity.HasOne(e => e.User)
                    .WithMany(e => e.Comments)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(e => e.ServicePost)
                    .WithMany(e => e.Comments)
                    .HasForeignKey(e => e.ServicePostId)
                    .OnDelete(DeleteBehavior.Cascade);

                
                entity.HasOne(e => e.ParentComment)
                    .WithMany(e => e.Replies)
                    .HasForeignKey(e => e.ParentCommentId)
                    .OnDelete(DeleteBehavior.Restrict);
            });

            builder.Entity<PostShare>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => new { e.ServicePostId, e.CreatedAt });
                entity.HasIndex(e => e.UserId);

                entity.HasOne(e => e.User)
                    .WithMany()
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(e => e.ServicePost)
                    .WithMany(e => e.Shares)
                    .HasForeignKey(e => e.ServicePostId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<ServiceRequest>(entity =>
            {
                entity.HasKey(e => e.Id);

                
                entity.HasIndex(e => new { e.Status, e.Category, e.CreatedAt });
                //entity.HasIndex(e => new { e.Location, e.Status })
                //    .HasMethod("GIST");
                entity.HasIndex(e => e.RequiredSkills).HasMethod("GIN");
                entity.HasIndex(e => new { e.UserId, e.CreatedAt });

                entity.HasOne(e => e.User)
                    .WithMany(e => e.ServiceRequests)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<Bid>(entity =>
            {
                entity.HasKey(e => e.Id);

                // Unique constraint: one bid per artisan per request
                entity.HasIndex(e => new { e.ServiceRequestId, e.ArtisanId }).IsUnique();
                entity.HasIndex(e => new { e.ServiceRequestId, e.Status, e.BidRankScore });
                entity.HasIndex(e => new { e.ArtisanId, e.CreatedAt });

                entity.HasOne(e => e.ServiceRequest)
                    .WithMany(e => e.Bids)
                    .HasForeignKey(e => e.ServiceRequestId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(e => e.Artisan)
                    .WithMany(e => e.Bids)
                    .HasForeignKey(e => e.ArtisanId)
                    .OnDelete(DeleteBehavior.Restrict);
            });



            
            builder.Entity<AuditLog>(entity =>
			{
				entity.HasKey(e => e.Id);
				entity.Property(e => e.Action).IsRequired();

				entity.HasIndex(e => e.UserId);
				entity.HasIndex(e => e.Action);
				entity.HasIndex(e => e.CreatedAt);
			});

            builder.Entity<Conversation>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.ServicePostId);
                entity.HasIndex(e => e.BookingId).IsUnique();
                entity.HasIndex(e => new { e.LastMessageAt, e.IsArchived });

                entity.HasOne(e => e.ServicePost)
                    .WithMany(e => e.RelatedConversations)
                    .HasForeignKey(e => e.ServicePostId)
                    .OnDelete(DeleteBehavior.SetNull);

                entity.HasOne(e => e.Booking)
                    .WithOne(e => e.Conversation)
                    .HasForeignKey<Conversation>(e => e.BookingId)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            builder.Entity<ConversationParticipant>(entity =>
            {
                entity.HasKey(e => e.Id);

                // Unique constraint: user can only be participant once per conversation
                entity.HasIndex(e => new { e.ConversationId, e.UserId }).IsUnique();
                entity.HasIndex(e => new { e.UserId, e.UnreadCount });

                entity.HasOne(e => e.Conversation)
                    .WithMany(e => e.Participants)
                    .HasForeignKey(e => e.ConversationId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(e => e.User)
                    .WithMany(e => e.ConversationParticipants)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<Message>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => new { e.ConversationId, e.CreatedAt });
                entity.HasIndex(e => new { e.SenderId, e.CreatedAt });

                entity.HasOne(e => e.Conversation)
                    .WithMany(e => e.Messages)
                    .HasForeignKey(e => e.ConversationId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(e => e.Sender)
                    .WithMany()
                    .HasForeignKey(e => e.SenderId)
                    .OnDelete(DeleteBehavior.Restrict);
            });

            builder.Entity<Review>(entity =>
            {
                entity.HasKey(e => e.Id);

                // Unique constraint: one review per booking
                entity.HasIndex(e => e.BookingId).IsUnique();
                entity.HasIndex(e => new { e.ArtisanId, e.CreatedAt });
                entity.HasIndex(e => new { e.ArtisanId, e.OverallRating });

                entity.HasOne(e => e.Booking)
                    .WithOne(e => e.Review)
                    .HasForeignKey<Review>(e => e.BookingId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(e => e.Reviewer)
                    .WithMany(e => e.ReviewsGiven)
                    .HasForeignKey(e => e.ReviewerId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(e => e.Artisan)
                    .WithMany(e => e.ReviewsReceived)
                    .HasForeignKey(e => e.ArtisanId)
                    .OnDelete(DeleteBehavior.Restrict);
            });

            builder.Entity<Notification>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => new { e.UserId, e.IsRead, e.CreatedAt });
                entity.HasIndex(e => new { e.UserId, e.Type, e.CreatedAt });

                entity.HasOne(e => e.User)
                    .WithMany(e => e.Notifications)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<UserActivity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => new { e.UserId, e.ActivityType, e.CreatedAt });
                entity.HasIndex(e => new { e.UserId, e.Category });

                // For recommendation engine queries
                entity.HasIndex(e => new { e.UserId, e.RelatedEntityType, e.RelatedEntityId });

                entity.HasOne(e => e.User)
                    .WithMany(e => e.Activities)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<PortfolioItem>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => new { e.ArtisanProfileId, e.DisplayOrder });
                entity.HasIndex(e => new { e.ArtisanProfileId, e.IsFeatured });

                entity.HasOne(e => e.ArtisanProfile)
                    .WithMany(e => e.Portfolio)
                    .HasForeignKey(e => e.ArtisanProfileId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

        }
    }
}