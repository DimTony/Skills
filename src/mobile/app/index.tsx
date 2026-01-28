import WelcomeSplash from "@/components/welcome";
import { useAuth } from "@/context/AuthContext";
import { Redirect } from "expo-router";
import { StyleSheet } from "react-native";

export default function Index() {
  const { user, authState, isReady } = useAuth();

  // Show splash while loading
  if (!isReady) {
    return <WelcomeSplash />;
  }

  // Redirect based on auth state
  if (authState === "authenticated" && user) {
    if (user?.userType === "Artisan") {
      return <Redirect href="/(artisan)" />;
    } else {
      return <Redirect href="/(user)" />;
    }
  }

  if (authState === "logged-out") {
    return <Redirect href="/login" />;
  }

  if (authState === "new-user") {
    return <Redirect href="/get-started" />;
  }

  return null;
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#007AFF",
    alignItems: "center",
    justifyContent: "center",
  },
  brand: {
    fontSize: 48,
    fontWeight: "bold",
    color: "white",
    marginBottom: 10,
  },
  tagline: {
    fontSize: 18,
    color: "white",
    opacity: 0.9,
  },
});

// import { useAuth } from "@/context/AuthContext";
// import { Redirect } from "expo-router";
// import * as SplashScreen from "expo-splash-screen";

// SplashScreen.preventAutoHideAsync();

// export default function Index() {
//   const { isAuthenticated, hasLoggedOutRecently, isLoading } = useAuth();

//   if (isLoading) return null;

//   SplashScreen.hideAsync();

//   if (isAuthenticated) {
//   }

//   if (hasLoggedOutRecently) {
//     return <Redirect href="/(auth)/login" />;
//   }

//   return <Redirect href="/(onboarding)/get-started" />;
// }
