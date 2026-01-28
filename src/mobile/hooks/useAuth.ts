import { useMutation } from "@tanstack/react-query";
import { useRouter } from "expo-router";
import { Alert } from "react-native";
import { authApi } from "../api/auth";
import { useAuth } from "../context/AuthContext";
import type {
  LoginPayload,
  RegisterUserPayload,
  RegisterAgentPayload,
} from "../types/api";
import { normalizeApiError, parseApiError } from "@/lib/parseError";
import { ApiError } from "@/api/client";

export const useLogin = () => {
  const router = useRouter();
  const { login } = useAuth();

  return useMutation({
    mutationFn: (payload: LoginPayload) => authApi.login(payload),
    onSuccess: async (data) => {
      // console.log("RES", data);

      await login(data.data.user, data.data.token);
    },
    onError: (error: ApiError) => {
      const apiError =
        error instanceof ApiError ? error : normalizeApiError(error);

      // console.error("LOGIN ERROR:", apiError.toJSON());

      Alert.alert("Error", apiError.message || "Login failed");
    },
  });
};

export const useRegisterUser = () => {
  const router = useRouter();
  const { login } = useAuth();

  return useMutation({
    mutationFn: (payload: RegisterUserPayload) => authApi.registerUser(payload),
    onSuccess: async (data) => {
      // await login(data.data.user, data.data.token);
      return data;
    },
    onError: (error: Error) => {
      const apiError =
        error instanceof ApiError ? error : normalizeApiError(error);

      // console.error("LOGIN ERROR:", apiError.toJSON());

      Alert.alert("Error", apiError.message || "Login failed");
    },
  });
};

export const useRegisterAgent = () => {
  const router = useRouter();
  const { login } = useAuth();

  return useMutation({
    mutationFn: (payload: RegisterAgentPayload) =>
      authApi.registerAgent(payload),
    onSuccess: async (data) => {
      // await login(data.data.user, data.data.token);
      return data;
    },
    onError: (error: Error) => {
      const apiError =
        error instanceof ApiError ? error : normalizeApiError(error);

      // console.error("LOGIN ERROR:", apiError.toJSON());

      Alert.alert("Error", apiError.message || "Login failed");
    },
  });
};
