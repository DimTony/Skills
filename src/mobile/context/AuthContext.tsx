import AsyncStorage from "@react-native-async-storage/async-storage";
import React, { createContext, useContext, useEffect, useState } from "react";

type AuthState = "loading" | "new-user" | "logged-out" | "authenticated";

interface User {
  id: string;
  email: string;
  userType: "User" | "Artisan";
  firstName: string;
  lastName: string;
  fullName?: string;
  businessName?: string;
  phoneNumber: string;
  profilePhoto?: string;
  servicePreferences?: string[];
  services?: Array<{
    id: string;
    name: string;
    category: string;
    pricingModel: "fixed" | "hourly" | "quote";
    minPrice?: number;
    maxPrice?: number;
    availability: string;
    notes?: string;
  }>;
}

interface AuthContextType {
  authState: AuthState;
  user: User | null;
  isReady: boolean;
  lastUserType: "User" | "Artisan" | null;
  login: (userData: User, token: string) => Promise<void>;
  logout: () => Promise<void>;
  completeOnboarding: () => Promise<void>;
  resetAppData: () => Promise<void>;
  updateUser: (userData: Partial<User>) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [authState, setAuthState] = useState<AuthState>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [isReady, setIsReady] = useState(false);
  const [lastUserType, setLastUserType] = useState<"User" | "Artisan" | null>(
    null,
  );

  useEffect(() => {
    checkAuthState();
  }, []);

  const checkAuthState = async () => {
    try {
      const minSplashTime = new Promise((resolve) => setTimeout(resolve, 3000));

      const [
        hasCompletedOnboarding,
        isLoggedIn,
        hasLoggedOut,
        lastUserTypeStored,
        storedUser,
        storedToken,
      ] = await Promise.all([
        AsyncStorage.getItem("habitera-hasCompletedOnboarding"),
        AsyncStorage.getItem("habitera-isLoggedIn"),
        AsyncStorage.getItem("habitera-hasLoggedOut"),
        AsyncStorage.getItem("habitera-lastUserType"),
        AsyncStorage.getItem("habitera-user"),
        AsyncStorage.getItem("habitera-token"),
        minSplashTime,
      ]);

      if (isLoggedIn === "true" && storedUser && storedToken) {
        const userData = JSON.parse(storedUser);
        setUser(userData);
        setAuthState("authenticated");
      } else if (hasLoggedOut === "true") {
        setAuthState("logged-out");
      } else if (hasCompletedOnboarding !== "true") {
        setAuthState("new-user");
      } else {
        setAuthState("logged-out");
      }

      if (lastUserTypeStored === "Artisan" || lastUserTypeStored === "User") {
        setLastUserType(lastUserTypeStored);
      }
    } catch (error) {
      console.error("Error checking auth state:", error);
      setAuthState("new-user");
    } finally {
      setIsReady(true);
    }
  };

  const login = async (userData: User, token: string) => {
    try {
      await AsyncStorage.multiSet([
        ["habitera-isLoggedIn", "true"],
        ["habitera-hasLoggedOut", "false"],
        ["habitera-user", JSON.stringify(userData)],
        ["habitera-token", token],
        [
          "habitera-lastUserType",
          userData.userType === "Artisan" ? "Artisan" : "User",
        ],
      ]);
      setUser(userData);
      setAuthState("authenticated");
    } catch (error) {
      console.error("Error during login:", error);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await AsyncStorage.multiSet([
        ["habitera-isLoggedIn", "false"],
        ["habitera-hasLoggedOut", "true"],
      ]);
      await AsyncStorage.multiRemove(["habitera-user", "habitera-token"]);
      setUser(null);
      setAuthState("logged-out");
    } catch (error) {
      console.error("Error during logout:", error);
      throw error;
    }
  };

  const completeOnboarding = async () => {
    await AsyncStorage.setItem("habitera-hasCompletedOnboarding", "true");
    setAuthState("logged-out");
  };

  const updateUser = async (userData: Partial<User>) => {
    try {
      const updatedUser = { ...user, ...userData } as User;
      await AsyncStorage.setItem("habitera-user", JSON.stringify(updatedUser));
      setUser(updatedUser);
    } catch (error) {
      console.error("Error updating user:", error);
      throw error;
    }
  };

  const resetAppData = async () => {
    try {
      await AsyncStorage.clear();
      setUser(null);
      setAuthState("new-user");
      console.log("AsyncStorage cleared successfully!");
    } catch (error) {
      console.error("Failed to clear AsyncStorage:", error);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        authState,
        user,
        isReady,
        lastUserType,
        login,
        logout,
        completeOnboarding,
        resetAppData,
        updateUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
