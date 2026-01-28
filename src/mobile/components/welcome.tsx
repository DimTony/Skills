import React, { useEffect, useRef } from "react";
import { Animated, StyleSheet, View } from "react-native";
import LogoIcon from "./icons/Logo";

const TEXT = "Skills";

const WelcomeSplash: React.FC = () => {
  const logoOpacity = useRef(new Animated.Value(0)).current;

  // Create one Animated.Value per character
  const charOpacities = useRef(
    TEXT.split("").map(() => new Animated.Value(0)),
  ).current;

  useEffect(() => {
    Animated.sequence([
      // Fade in logo
      Animated.timing(logoOpacity, {
        toValue: 1,
        duration: 800,
        useNativeDriver: true,
      }),

      Animated.delay(300),

      // Staggered character fade-in
      Animated.stagger(
        80, // delay between characters
        charOpacities.map((opacity) =>
          Animated.timing(opacity, {
            toValue: 1,
            duration: 300,
            useNativeDriver: true,
          }),
        ),
      ),
    ]).start();
  }, []);

  return (
    <View style={styles.container}>
      <View style={styles.content}>
        <Animated.View style={{ opacity: logoOpacity }}>
          <LogoIcon width={32} height={33} fill="#FFFFFF" />
        </Animated.View>

        <View style={styles.textContainer}>
          {TEXT.split("").map((char, index) => (
            <Animated.Text
              key={`${char}-${index}`}
              style={[
                styles.text,
                {
                  opacity: charOpacities[index],
                },
              ]}
            >
              {char}
            </Animated.Text>
          ))}
        </View>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#5f8179",
  },
  content: {
    flexDirection: "row",
    alignItems: "center",
  },
  textContainer: {
    flexDirection: "row",
    marginLeft: 8,
  },
  text: {
    fontSize: 24,
    fontWeight: "500",
    color: "#FFFFFF",
  },
});

export default WelcomeSplash;
