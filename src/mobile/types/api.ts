export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  fullName?: string;
  phoneNumber: string;
  userType: "User" | "Artisan";
  businessName?: string;
  servicePreferences?: string[];
}

export interface AuthResponse {
  success: boolean;
  data: {
    user: User;
    token: string;
  };
  message?: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface RegisterUserPayload {
  email: string;
  password: string;
  fullName: string;
  firstName: string;
  userType: string;
  lastName: string;
  phoneNumber: string;
  servicePreferences: string[];
}

export interface RegisterAgentPayload {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  userType: string;
  phoneNumber: string;
  businessName: string;
  service: {
    name: string;
    category: string;
    pricingModel: "fixed" | "hourly" | "quote";
    minPrice?: number;
    maxPrice?: number;
    availability: string;
    notes?: string;
  };
}
