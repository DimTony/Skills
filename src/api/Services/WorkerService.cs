using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Skills.Data;
using Skills.DTOs;
using Skills.Models;
using Skills.Services;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Skills.Services
{
    public interface IWorkerService
    {
        Task CleanupOldAuditLogsAsync();
    }

    public class WorkerService : IWorkerService
    {
        private readonly AppDbContext _context;
        private readonly ILoggingService _logger;

        public WorkerService(AppDbContext context, ILoggingService loggingService)
        {
            _context = context;
            _logger = loggingService;
        }

        public async Task CleanupOldAuditLogsAsync()
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-90);

            await _context.AuditLogs
                .Where(l => l.CreatedAt < cutoffDate)
                .ExecuteDeleteAsync();
        }

        private async Task CheckAndAlertOnAnomalies(string correlationId)
        {
            var last5Minutes = DateTime.UtcNow.AddMinutes(-5);

            var failedLogins = await _context.AuditLogs
                .Where(l => l.Action == "LoginAttempt" &&
                       !l.Success &&
                       l.CreatedAt >= last5Minutes)
                .CountAsync();

            if (failedLogins > 50) // Threshold for alert
            {
                _logger.LogWarning("ALERT: High volume of failed logins detected",
                    new { CorrelationId = correlationId, Count = failedLogins });
                // Send alert to monitoring system
            }
        }


    }



}



