import { AuthProvider, useAuth } from "@/context/AuthContext";
import { Slot, useRouter, useSegments } from "expo-router";
import { useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 5 * 60 * 1000, // 5 minutes
      gcTime: 10 * 60 * 1000, // 10 minutes (formerly cacheTime)
    },
  },
});

function RootLayoutNav() {
  const { user, authState, isReady } = useAuth();
  const segments = useSegments();
  const router = useRouter();

  useEffect(() => {
    if (!isReady) return;

    const inAuthGroup = segments[0] === "(user)" || segments[0] === "(artisan)";

    if (authState === "authenticated" && !inAuthGroup && user) {
      if (user?.userType === "Artisan") {
        router.replace("/(artisan)"); // or "/(tabs)/artisan" depending on your routes
      } else {
        router.replace("/(user)"); // or "/(tabs)/user"
      }
    } else if (authState === "logged-out" && inAuthGroup) {
      router.replace("/login");
    } else if (authState === "new-user" && inAuthGroup) {
      router.replace("/get-started");
    }
  }, [authState, segments, isReady]);

  return <Slot />;
}

export default function RootLayout() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RootLayoutNav />
      </AuthProvider>
    </QueryClientProvider>
  );
}

// import {
//   DarkTheme,
//   DefaultTheme,
//   ThemeProvider,
// } from "@react-navigation/native";
// import { Stack } from "expo-router";
// import { StatusBar } from "expo-status-bar";
// import "react-native-reanimated";

// import { AuthProvider } from "@/context/AuthContext";
// import { useColorScheme } from "@/hooks/use-color-scheme";

// export const unstable_settings = {
//   anchor: "(tabs)",
// };

// export default function RootLayout() {
//   const colorScheme = useColorScheme();

//   return (
//     <ThemeProvider value={colorScheme === "dark" ? DarkTheme : DefaultTheme}>
//       <AuthProvider>
//         <Stack screenOptions={{ headerShown: false }}>
//           <Stack.Screen name="index" />
//           <Stack.Screen name="get-started" />
//           <Stack.Screen name="login" />
//           <Stack.Screen name="(tabs)" />
//           <Stack.Screen
//             name="modal"
//             options={{ presentation: "modal", title: "Modal" }}
//           />
//         </Stack>
//         {/* <Stack
//           initialRouteName="welcome"
//           screenOptions={{ headerShown: false }}
//         /> */}
//         <StatusBar style="auto" />
//       </AuthProvider>
//     </ThemeProvider>
//   );
// }
