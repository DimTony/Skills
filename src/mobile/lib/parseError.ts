import { ApiError } from "@/api/client";


export function normalizeApiError(error: any, endpoint?: string): ApiError {
  if (error instanceof ApiError) {
    return error;
  }

  const status = error?.status;

  // ASP.NET validation errors
  if (error?.errors) {
    const messages = Object.values(error.errors).flat().filter(Boolean);
    return new ApiError(messages.join("\n"), status, error, endpoint);
  }

  // Auth / custom API error
  if (error?.error || error?.message) {
    return new ApiError(error.error || error.message, status, error, endpoint);
  }

  // Network / unknown
  if (error instanceof Error) {
    return new ApiError(error.message, undefined, error, endpoint);
  }

  return new ApiError(
    "Something went wrong. Please try again.",
    undefined,
    error,
    endpoint,
  );
}


export function parseApiError(error: any): string {
  // If it's a thrown Error
  if (error instanceof Error) {
    return error.message;
  }

  // ASP.NET validation errors
  if (error?.errors && typeof error.errors === "object") {
    const messages = Object.values(error.errors).flat().filter(Boolean);

    if (messages.length > 0) {
      return messages.join("\n");
    }
  }

  // Fallbacks
  return (
    error?.message || error?.title || "Something went wrong. Please try again."
  );
}
