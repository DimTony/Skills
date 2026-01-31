import { normalizeApiError } from "@/lib/parseError";
import AsyncStorage from "@react-native-async-storage/async-storage";

// const API_BASE_URL = "https://skills-eea5.onrender.com";
// const API_BASE_URL = "https://skills-production-83eb.up.railway.app";
const API_BASE_URL = "http://172.20.10.6:5013";
// Test-NetConnection -ComputerName 192.168.1.100 -Port 5000

export class ApiError extends Error {
  status?: number;
  data?: any;
  endpoint?: string;

  constructor(message: string, status?: number, data?: any, endpoint?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
    this.endpoint = endpoint;
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      status: this.status,
      data: this.data,
      endpoint: this.endpoint,
    };
  }
}

class ApiClient {
  private baseURL: string;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
  }

  private async getAuthToken(): Promise<string | null> {
    return await AsyncStorage.getItem("habitera-token");
  }

  async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = await this.getAuthToken();

    const config: RequestInit = {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
    };

     console.log("API Request:", endpoint);

    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, config);
      const data = await response.json();

      console.log("API Response:", endpoint, {
        status: response.status,
        ok: response.ok,
        data,
      });

      // ✅ USE HTTP STATUS
      if (!response.ok) {
        throw normalizeApiError(data, endpoint);
      }

      return data;
    } catch (error) {
      // ✅ ALWAYS throw ApiError
      throw normalizeApiError(error, endpoint);
    }
  }

  get<T>(endpoint: string) {
    return this.request<T>(endpoint, { method: "GET" });
  }

  post<T>(endpoint: string, body: any) {
    return this.request<T>(endpoint, {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  put<T>(endpoint: string, body: any) {
    return this.request<T>(endpoint, {
      method: "PUT",
      body: JSON.stringify(body),
    });
  }

  delete<T>(endpoint: string) {
    return this.request<T>(endpoint, { method: "DELETE" });
  }
}

export const apiClient = new ApiClient(API_BASE_URL);
