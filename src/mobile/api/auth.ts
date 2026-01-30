import { apiClient } from "./client";
import type {
  AuthResponse,
  LoginPayload,
  RegisterUserPayload,
  RegisterAgentPayload,
  ResendOTPPayload,
} from "../types/api";

export const authApi = {
  login: (payload: LoginPayload) => {
    // console.log("PPP", payload);
    const response = apiClient.post<AuthResponse>(
      "/api/Authentication/Login",
      payload,
    );
    // console.log("RES", response);
    return response;
  },

  registerUser: (payload: RegisterUserPayload) => {
    console.log("PPP", payload);
    const response = apiClient.post<AuthResponse>(
      "/api/Authentication/Register",
      payload,
    );
    return response;
  },

  registerAgent: (payload: RegisterAgentPayload) => {
    console.log("PPP", payload);
    const response = apiClient.post<AuthResponse>(
      "/api/Authentication/Register",
      payload,
    );
    return response;
  },

  resendOTP: (payload: ResendOTPPayload) => {
    const response = apiClient.post(
      "/api/Authentication/ResendVerification",
      payload,
    );
    return response;
  },

  logout: () => apiClient.post("/api/auth/logout", {}),
};
