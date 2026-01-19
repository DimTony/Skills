namespace Skills.DTOs
{
    public class OperationResult
    {
        public bool Succeeded { get; set; }
        public string Message { get; set; } = string.Empty;

        public static OperationResult Success() => new() { Succeeded = true };
        public static OperationResult Failure(string message) => new() { Succeeded = false, Message = message };
    }

    public class NonPaginatedResponse<T>
    {
        public bool Success { get; set; }
        public int StatusCode { get; set; }
        public string Message { get; set; } = string.Empty;
        public T? Data { get; set; }
        public object? Error { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        // Success response factory methods
        public static NonPaginatedResponse<T> SuccessResponse(T? data, string message = "Success", int statusCode = 200)
        {
            return new NonPaginatedResponse<T>
            {
                Success = true,
                StatusCode = statusCode,
                Message = message,
                Data = data,
                Error = null
            };
        }

        // Error response factory methods
        public static NonPaginatedResponse<T> ErrorResponse(string message, int statusCode = 400, object? error = null)
        {
            return new NonPaginatedResponse<T>
            {
                Success = false,
                StatusCode = statusCode,
                Message = message,
                Data = default(T),
                Error = error
            };
        }
    }

    public class PaginatedRequest
    {
        public int PageNumber { get; set; } = 1;      // Default to first page
        public int PageSize { get; set; } = 10;       // Default page size
        public string? SearchWord { get; set; }       // Optional search/filter term
    }

    public class PaginatedResponse<T>
    {
        public bool Success { get; set; }
        public int StatusCode { get; set; }
        public string Message { get; set; } = string.Empty;
        public IEnumerable<T>? Data { get; set; }   // The actual records
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public int TotalRecords { get; set; }
        public int TotalPages { get; set; }
        public bool HasNextPage => PageNumber < TotalPages;
        public bool HasPreviousPage => PageNumber > 1;
        public object? Error { get; set; }

        // Success response factory
        public static PaginatedResponse<T> SuccessResponse(
            IEnumerable<T> data,
            int count,
            int pageNumber,
            int pageSize,
            string message = "Success",
            int statusCode = 200)
        {
            return new PaginatedResponse<T>
            {
                Success = true,
                StatusCode = statusCode,
                Message = message,
                Data = data,
                TotalRecords = count,
                PageNumber = pageNumber,
                PageSize = pageSize,
                TotalPages = (int)Math.Ceiling(count / (double)pageSize),
            };
        }

        // Error response factory
        public static PaginatedResponse<T> ErrorResponse(
            string message,
            int statusCode = 400,
            object? error = null)
        {
            return new PaginatedResponse<T>
            {
                Success = false,
                StatusCode = statusCode,
                Message = message,
                Data = default(IEnumerable<T>),
                TotalRecords = 0,
                PageNumber = 0,
                PageSize = 0,
                TotalPages = 0,
                Error = error
            };
        }
    }

}
