using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Skills.Services;
using Skills.DTOs;

namespace Skills.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> RegisterUser([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            //var ipAddress = GetIpAddress();
            request.IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            request.DeviceInfo = HttpContext.Request.Headers["User-Agent"].ToString();

            var result = await _authService.RegisterAsync(request);

            if (result.Succeeded)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Get IP and device info from request
            request.IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            request.UserAgent = HttpContext.Request.Headers["User-Agent"].ToString();
            request.DeviceInfo = HttpContext.Request.Headers["User-Agent"].ToString();

            var result = await _authService.LoginAsync(request);

            if (result.Succeeded)
            {
                return Ok(result);
            }

            return Unauthorized(result);

        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            if (string.IsNullOrEmpty(request.RefreshToken))
                return BadRequest(new { error = "Refresh token is required" });

            var result = await _authService.RefreshTokenAsync(request.RefreshToken);

            if (result.Succeeded)
            {
                return Ok(result);
            }

            return Unauthorized(result);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequest request)
        {
            if (string.IsNullOrEmpty(request.RefreshToken))
                return BadRequest(new { error = "Refresh token is required" });

            var success = await _authService.RevokeTokenAsync(request.RefreshToken);

            if (!success)
                return BadRequest(new { error = "Failed to revoke token" });

            return Ok(new { message = "Logout successful" });
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            if (string.IsNullOrEmpty(request.Email))
                return BadRequest(new { error = "Email is required" });

            var success = await _authService.SendPasswordResetTokenAsync(request.Email);

            // Always return success to prevent email enumeration
            return Ok(new { message = "If the email exists, a password reset link has been sent." });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var success = await _authService.ResetPasswordAsync(request);

            if (!success)
                return BadRequest(new { error = "Invalid or expired token" });

            return Ok(new { message = "Password reset successful" });
        }

        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var success = await _authService.ChangePasswordAsync(userId, request);

            if (!success)
                return BadRequest(new { error = "Failed to change password. Please check your current password." });

            return Ok(new { message = "Password changed successfully" });
        }

        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromQuery] string token)
        {
            if (string.IsNullOrEmpty(token))
                return BadRequest(new { error = "Token is required" });

            var success = await _authService.VerifyEmailAsync(token);

            if (!success)
                return BadRequest(new { error = "Invalid or expired verification token" });

            return Ok(new { message = "Email verified successfully" });
        }

        //[Authorize]
        [HttpPost("resend-verification-email")]
        public async Task<IActionResult> ResendVerificationEmail([FromBody] ResendCodeRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            //var ipAddress = GetIpAddress();
            request.IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            request.DeviceInfo = HttpContext.Request.Headers["User-Agent"].ToString();

            var result = await _authService.ResendVerificationCodeEndpointAsync(request);

            if (result.Succeeded)
            {
                return Ok(result);
            }

            return BadRequest(result);

            //var success = await _authService.SendEmailVerificationTokenAsync(userId);

            //if (!success)
            //    return BadRequest(new { error = "Failed to send verification email" });

            //return Ok(new { message = "Verification email sent successfully" });
        }

        //[HttpPost("send-otp")]
        //public async Task<IActionResult> SendOtp([FromBody] SendOtpRequest request)
        //{
        //    if (string.IsNullOrEmpty(request.PhoneNumber))
        //        return BadRequest(new { error = "Phone number is required" });

        //    var success = await _authService.SendOtpAsync(request.PhoneNumber);

        //    if (!success)
        //        return BadRequest(new { error = "Failed to send OTP" });

        //    return Ok(new { message = "OTP sent successfully" });
        //}

        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequest request)
        {
            if (string.IsNullOrEmpty(request.PhoneNumber) || string.IsNullOrEmpty(request.Otp))
                return BadRequest(new { error = "Phone number and OTP are required" });

            var success = await _authService.VerifyOtpAsync(request.PhoneNumber, request.Otp);

            if (!success)
                return BadRequest(new { error = "Invalid or expired OTP" });

            return Ok(new { message = "OTP verified successfully" });
        }

        [Authorize]
        [HttpGet("me")]
        public IActionResult GetCurrentUser()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var email = User.FindFirstValue(ClaimTypes.Email);
            var userType = User.FindFirstValue("userType");
            var fullName = User.FindFirstValue("fullName");

            return Ok(new
            {
                id = userId,
                email,
                userType,
                fullName
            });
        }
    }


}