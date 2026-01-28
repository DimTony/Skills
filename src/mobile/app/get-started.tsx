import { useState, useRef } from "react";
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ImageBackground,
  Animated,
  Dimensions,
} from "react-native";
import { useRouter, Redirect } from "expo-router";
import { useAuth } from "@/context/AuthContext";


const { width, height } = Dimensions.get("window");

// Define your onboarding screens data
const ONBOARDING_SCREENS = [
  {
    image: require("../assets/images/onboarding-1.jpg"),
    title: "Discover Skilled Artisans",
    description:
      "Browse and connect with trusted local artisans for any service you need, from home repairs to creative projects.",
  },
  {
    image: require("../assets/images/onboarding-2.jpg"),
    title: "Book Services Effortlessly",
    description:
      "Schedule appointments in just a few taps and manage your bookings seamlessly through the app.",
  },
  {
    image: require("../assets/images/onboarding-3.jpg"),
    title: "Track Your Projects",
    description:
      "Stay updated on progress, receive notifications, and communicate directly with your artisan to ensure quality results.",
  },
  {
    image: require("../assets/images/onboarding-4.jpg"),
    title: "Achieve Your Home & Lifestyle Goals",
    description:
      "From repairs to renovations or custom creations, get the job done efficiently and reliably with Habitera.",
  },
];


export default function GetStarted() {
  const router = useRouter();
  const { completeOnboarding, authState } = useAuth();
  const [currentIndex, setCurrentIndex] = useState(0);
  const fadeAnim = useRef(new Animated.Value(1)).current;

  // Protect route - only new users should see this
  if (authState !== "new-user") {
    return <Redirect href="/" />;
  }

  const isLastScreen = currentIndex === ONBOARDING_SCREENS.length - 1;

  const handleNext = () => {
    if (isLastScreen) return;

    // Fade out current screen
    Animated.timing(fadeAnim, {
      toValue: 0,
      duration: 200,
      useNativeDriver: true,
    }).start(() => {
      // Move to next screen
      setCurrentIndex((prev) => prev + 1);

      // Fade in next screen
      Animated.timing(fadeAnim, {
        toValue: 1,
        duration: 200,
        useNativeDriver: true,
      }).start();
    });
  };

  const handleSkip = () => {
    // Fade out and jump to last screen
    Animated.timing(fadeAnim, {
      toValue: 0,
      duration: 200,
      useNativeDriver: true,
    }).start(() => {
      setCurrentIndex(ONBOARDING_SCREENS.length - 1);

      Animated.timing(fadeAnim, {
        toValue: 1,
        duration: 200,
        useNativeDriver: true,
      }).start();
    });
  };

  const handleContinueAsUser = async () => {
    await completeOnboarding();
    router.replace("/login?userType=user");
  };

  const handleContinueAsAgent = async () => {
    await completeOnboarding();
    router.replace("/login?userType=agent");
  };

  const currentScreen = ONBOARDING_SCREENS[currentIndex];

  return (
    <ImageBackground
      source={currentScreen.image}
      style={styles.container}
      resizeMode="cover"
    >
      <Animated.View style={[styles.overlay, { opacity: fadeAnim }]}>
        {/* Skip Button - Show only on first 3 screens */}
        {!isLastScreen && (
          <TouchableOpacity style={styles.skipButton} onPress={handleSkip}>
            <Text style={styles.skipText}>Skip</Text>
          </TouchableOpacity>
        )}

        {/* Content */}
        <View style={styles.content}>
          <View style={styles.textContainer}>
            <Text style={styles.title}>{currentScreen.title}</Text>
            <Text style={styles.description}>{currentScreen.description}</Text>
          </View>

          {/* Pagination Dots */}
          <View style={styles.pagination}>
            {ONBOARDING_SCREENS.map((_, index) => (
              <View
                key={index}
                style={[styles.dot, index === currentIndex && styles.activeDot]}
              />
            ))}
          </View>

          {/* Bottom Buttons */}
          {isLastScreen ? (
            // Last screen: Two buttons side by side
            <View style={styles.finalButtons}>
              <TouchableOpacity
                style={[styles.button, styles.userButton]}
                onPress={handleContinueAsUser}
              >
                <Text style={styles.primaryButtonText}>Continue as User</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.button, styles.agentButton]}
                onPress={handleContinueAsAgent}
              >
                <Text style={styles.buttonText}>Continue as Agent</Text>
              </TouchableOpacity>
            </View>
          ) : (
            // First 3 screens: Right arrow button
            <TouchableOpacity style={styles.nextButton} onPress={handleNext}>
              <Text style={styles.nextArrow}>→</Text>
            </TouchableOpacity>
          )}
        </View>
      </Animated.View>
    </ImageBackground>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    width: width,
    height: height,
  },
  overlay: {
    flex: 1,
    backgroundColor: "rgba(0, 0, 0, 0.4)", // Dark overlay for better text visibility
  },
  skipButton: {
    position: "absolute",
    top: 60,
    right: 20,
    paddingHorizontal: 16,
    paddingVertical: 8,
    zIndex: 10,
  },
  skipText: {
    color: "#FFFFFF",
    fontSize: 16,
    fontWeight: "600",
  },
  content: {
    flex: 1,
    justifyContent: "flex-end",
    paddingHorizontal: 20,
    paddingBottom: 60,
  },
  textContainer: {
    marginBottom: 40,
  },
  title: {
    fontSize: 32,
    fontWeight: "bold",
    color: "#FFFFFF",
    marginBottom: 16,
  },
  description: {
    fontSize: 16,
    color: "#FFFFFF",
    lineHeight: 24,
    opacity: 0.9,
  },
  pagination: {
    flexDirection: "row",
    justifyContent: "center",
    marginBottom: 40,
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: "rgba(255, 255, 255, 0.4)",
    marginHorizontal: 4,
  },
  activeDot: {
    width: 24,
    backgroundColor: "#FFFFFF",
  },
  nextButton: {
    alignSelf: "center",
    width: 60,
    height: 60,
    borderRadius: 30,
    backgroundColor: "#FFFFFF",
    alignItems: "center",
    justifyContent: "center",
  },
  nextArrow: {
    fontSize: 24,
    color: "#5f8179",
    fontWeight: "bold",
  },
  finalButtons: {
    flexDirection: "row",
    gap: 12,
  },
  button: {
    flex: 1,
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: "center",
  },
  userButton: {
    backgroundColor: "#FFFFFF",
  },
  agentButton: {
    backgroundColor: "#5f8179",
  },
  primaryButtonText: {
    fontSize: 16,
    fontWeight: "600",
    color: "#5f8179",
  },
  buttonText: {
    fontSize: 16,
    fontWeight: "600",
    color: "#FFFFFF",
  },
});
