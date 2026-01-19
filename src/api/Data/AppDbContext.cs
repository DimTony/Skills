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
		public DbSet<Booking> Bookings { get; set; }
		public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }
		public DbSet<EmailVerificationToken> EmailVerificationTokens { get; set; }
		public DbSet<ServicePreference> ServicePreferences { get; set; }
		public DbSet<AuditLog> AuditLogs { get; set; }

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
				entity.HasIndex(e => e.PhoneNumber);
				entity.HasIndex(e => e.UserType);
				entity.HasIndex(e => e.Status);
			});

			// ArtisanProfile configuration
			builder.Entity<ArtisanProfile>(entity =>
			{
				entity.HasKey(e => e.Id);
				entity.Property(e => e.BusinessName).HasMaxLength(200);
				entity.Property(e => e.Rating).HasColumnType("decimal(3,2)");

				entity.HasOne(e => e.User)
					.WithOne(u => u.ArtisanProfile)
					.HasForeignKey<ArtisanProfile>(e => e.UserId)
					.OnDelete(DeleteBehavior.Cascade);

				entity.HasIndex(e => e.UserId).IsUnique();
				entity.HasIndex(e => e.Rating);
				entity.HasIndex(e => e.Verified);
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

			// Booking configuration
			builder.Entity<Booking>(entity =>
			{
				entity.HasKey(e => e.Id);

				entity.HasOne(e => e.User)
					.WithMany()
					.HasForeignKey(e => e.UserId)
					.OnDelete(DeleteBehavior.Restrict);

				entity.HasOne(e => e.Service)
					.WithMany()
					.HasForeignKey(e => e.ServiceId)
					.OnDelete(DeleteBehavior.Restrict);

				entity.HasIndex(e => e.UserId);
				entity.HasIndex(e => e.ServiceId);
				entity.HasIndex(e => e.Status);
				entity.HasIndex(e => e.BookingDate);
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
			// AuditLog configuration
			builder.Entity<AuditLog>(entity =>
			{
				entity.HasKey(e => e.Id);
				entity.Property(e => e.Action).IsRequired();

				entity.HasIndex(e => e.UserId);
				entity.HasIndex(e => e.Action);
				entity.HasIndex(e => e.CreatedAt);
			});
		}
	}
}