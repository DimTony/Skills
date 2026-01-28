import StepIndicator from "@/components/step-indicator";
import { useAuth } from "@/context/AuthContext";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { Redirect, useLocalSearchParams, useRouter } from "expo-router";
import { useEffect, useState } from "react";
import {
  Alert,
  Image,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import { useLogin, useRegisterUser, useRegisterAgent } from "@/hooks/useAuth";

const SERVICE_CATEGORIES = [
  "Plumbing",
  "Electrical",
  "Cleaning",
  "Painting",
  "Carpentry",
  "HVAC",
  "Landscaping",
  "Moving",
  "Handyman",
  "Other",
];

const PRICING_MODELS = [
  { value: "fixed", label: "Fixed Price" },
  { value: "hourly", label: "Hourly Rate" },
  { value: "quote", label: "Quote-based" },
];

/* ---------------------------
   Main Login Screen
---------------------------- */

export default function Login() {
  const loginMutation = useLogin();
  const registerUserMutation = useRegisterUser();
  const registerAgentMutation = useRegisterAgent();
  const router = useRouter();
  const { userType } = useLocalSearchParams<{ userType?: string }>();
  const { user, login, authState, lastUserType, resetAppData } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isRegister, setIsRegister] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [currentUserType, setCurrentUserType] = useState<"User" | "Artisan">(
    userType === "Artisan" ? "Artisan" : lastUserType || "User",
  );

  // Agent registration fields
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [businessName, setBusinessName] = useState("");
  const [agentRegisterStep, setAgentRegisterStep] = useState<1 | 2>(1);

  // User registration fields
  const [fullName, setFullName] = useState("");
  const [userRegisterStep, setUserRegisterStep] = useState<1 | 2>(1);
  const [selectedServices, setSelectedServices] = useState<string[]>([]);

  // Agent service fields (step 2)
  const [serviceName, setServiceName] = useState("");
  const [serviceCategory, setServiceCategory] = useState("");
  const [pricingModel, setPricingModel] = useState<
    "fixed" | "hourly" | "quote"
  >("fixed");
  const [minPrice, setMinPrice] = useState("");
  const [maxPrice, setMaxPrice] = useState("");
  const [availability, setAvailability] = useState("");
  const [serviceNotes, setServiceNotes] = useState("");
  const [showCategoryPicker, setShowCategoryPicker] = useState(false);
  const [showPricingPicker, setShowPricingPicker] = useState(false);
  const [showOTPView, setShowOTPView] = useState(false);
  const [otpCode, setOtpCode] = useState(["", "", "", "", "", ""]);
  const [registrationEmail, setRegistrationEmail] = useState("");
  const [isVerifyingOTP, setIsVerifyingOTP] = useState(false);
  // useEffect(() => {
  //   resetAppData();
  // }, []);
  useEffect(() => {
    if (authState === "authenticated" && user) {
      // adjust the route paths to match your app routing structure
      if (user?.userType === "Artisan") {
        router.replace("/(artisan)"); // or "/(tabs)/artisan" depending on your routes
      } else {
        router.replace("/(user)"); // or "/(tabs)/user"
      }
    }
  }, [authState, user, router]);
  /* ---------------------------
     Persist user type
  ---------------------------- */
  useEffect(() => {
    AsyncStorage.setItem("habitera-lastUserType", currentUserType);
  }, [currentUserType]);

  /* ---------------------------
     Clear form when switching modes
  ---------------------------- */
  useEffect(() => {
    // Clear all fields except when moving between agent steps
    if (!(currentUserType === "Artisan" && isRegister)) {
      setEmail("");
      setPassword("");
      setConfirmPassword("");
      setFullName("");
      setFirstName("");
      setLastName("");
      setPhoneNumber("");
      setBusinessName("");
      setServiceName("");
      setServiceCategory("");
      setPricingModel("fixed");
      setMinPrice("");
      setMaxPrice("");
      setAvailability("");
      setServiceNotes("");
      setSelectedServices([]);
    }

    // Reset steps
    setAgentRegisterStep(1);
    setUserRegisterStep(1);
  }, [isRegister, currentUserType]);

  /* ---------------------------
     Protect Routes
  ---------------------------- */
  if (authState === "authenticated") {
    return null;
  }

  if (authState === "new-user") {
    return <Redirect href="/get-started" />;
  }

  const userTypeLabel = currentUserType === "Artisan" ? "Artisan" : "User";

  /* ---------------------------
     Toggle Service Selection (User Step 2)
  ---------------------------- */
  const toggleService = (service: string) => {
    setSelectedServices((prev) =>
      prev.includes(service)
        ? prev.filter((s) => s !== service)
        : [...prev, service],
    );
  };

  /* ---------------------------
     Auth Handler
  ---------------------------- */
  const handleAuth = async () => {
    if (!email || !password) {
      Alert.alert("Error", "Please fill in all fields");
      return;
    }

    if (isRegister && password !== confirmPassword) {
      Alert.alert("Error", "Passwords do not match");
      return;
    }

    // User registration step 1
    if (isRegister && currentUserType === "User" && userRegisterStep === 1) {
      if (!fullName || !firstName || !lastName || !phoneNumber) {
        Alert.alert("Error", "Please fill in all required fields");
        return;
      }
      setUserRegisterStep(2);
      return;
    }

    // User registration step 2

    if (isRegister && currentUserType === "User" && userRegisterStep === 2) {
      if (selectedServices.length === 0) {
        Alert.alert("Error", "Please select at least one service preference");
        return;
      }

      try {
        await registerUserMutation.mutateAsync({
          email,
          password,
          fullName,
          firstName,
          lastName,
          userType: "User",
          phoneNumber,
          servicePreferences: selectedServices,
        });

        // On success, show OTP view
        setRegistrationEmail(email);
        setShowOTPView(true);
      } catch (error) {
        // Error handling is done in the mutation
      }
      return;
    }

    // Agent registration step 1
    if (
      isRegister &&
      currentUserType === "Artisan" &&
      agentRegisterStep === 1
    ) {
      if (
        // !fullName ||
        !firstName ||
        !lastName ||
        !phoneNumber ||
        !businessName
      ) {
        Alert.alert("Error", "Please fill in all required fields");
        return;
      }
      setAgentRegisterStep(2);
      return;
    }

    // Agent registration step 2
    if (
      isRegister &&
      currentUserType === "Artisan" &&
      agentRegisterStep === 2
    ) {
      if (!serviceName || !serviceCategory || !availability) {
        Alert.alert("Error", "Please fill in all required service fields");
        return;
      }

      if (pricingModel !== "quote" && (!minPrice || !maxPrice)) {
        Alert.alert("Error", "Please enter pricing range");
        return;
      }

      try {
        await registerAgentMutation.mutateAsync({
          email,
          password,
          firstName,
          lastName,
          userType: 'Artisan',
          phoneNumber,
          businessName,
          service: {
            name: serviceName,
            category: serviceCategory,
            pricingModel,
            minPrice:
              pricingModel !== "quote" ? parseFloat(minPrice) : undefined,
            maxPrice:
              pricingModel !== "quote" ? parseFloat(maxPrice) : undefined,
            availability,
            notes: serviceNotes,
          },
        });

        // On success, show OTP view
        setRegistrationEmail(email);
        setShowOTPView(true);
      } catch (error) {
        // Error handling is done in the mutation
      }
      return;
    }

    // Regular login
    loginMutation.mutate({ email, password });
  };

  const handleOTPVerification = async () => {
    const otp = otpCode.join("");

    if (otp.length !== 6) {
      Alert.alert("Error", "Please enter all 6 digits");
      return;
    }

    setIsVerifyingOTP(true);

    try {
      // Call your OTP verification API
      const response = await fetch("YOUR_API_URL/api/auth/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: registrationEmail,
          otp: otp,
        }),
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        Alert.alert("Error", result.message || "OTP verification failed");
        setIsVerifyingOTP(false);
        return;
      }

      // OTP verified successfully, now login
      loginMutation.mutate({
        email: registrationEmail,
        password: password,
      });
    } catch (error) {
      console.error("OTP verification error:", error);
      Alert.alert("Error", "An error occurred during verification");
      setIsVerifyingOTP(false);
    }
  };

  const handleOTPChange = (value: string, index: number) => {
    if (value.length > 1) return;

    const newOTP = [...otpCode];
    newOTP[index] = value;
    setOtpCode(newOTP);

    // Auto-focus next input
    if (value && index < 5) {
      // You'll need to use refs for auto-focus
    }
  };

  const isLoading =
    loginMutation.isPending ||
    registerUserMutation.isPending ||
    registerAgentMutation.isPending;

  /* ---------------------------
     Render
  ---------------------------- */
  return showOTPView ? (
    <>
    <View style={styles.header}>
      <Text style={styles.welcomeText}>Verify your account ✉️</Text>
      <Text style={styles.title}>
        Enter the 6-digit code sent to {registrationEmail}
      </Text>
    </View>

    <View style={styles.otpContainer}>
      {otpCode.map((digit, index) => (
        <TextInput
          key={index}
          style={styles.otpInput}
          value={digit}
          onChangeText={(value) => handleOTPChange(value, index)}
          keyboardType="number-pad"
          maxLength={1}
          textAlign="center"
        />
      ))}
    </View>

    <TouchableOpacity style={styles.resendButton}>
      <Text style={styles.resendText}>
        Didn't receive code? <Text style={styles.linkText}>Resend</Text>
      </Text>
    </TouchableOpacity>

    <TouchableOpacity
      style={styles.button}
      onPress={handleOTPVerification}
      disabled={isVerifyingOTP || loginMutation.isPending}
    >
      <Text style={styles.buttonText}>
        {isVerifyingOTP || loginMutation.isPending ? "Verifying..." : "Verify & Continue"}
      </Text>
    </TouchableOpacity>

    <TouchableOpacity
      onPress={() => {
        setShowOTPView(false);
        setOtpCode(['', '', '', '', '', '']);
      }}
      style={styles.backButton}
    >
      <Text style={styles.backButtonText}>← Back to registration</Text>
    </TouchableOpacity>
    </>
  ) : (
    <>
      <KeyboardAvoidingView
        style={styles.container}
        behavior={Platform.OS === "ios" ? "padding" : "height"}
      >
        {/* Fixed Header - Toggle Sign In/Sign Up */}
        <View style={styles.fixedHeader}>
          <TouchableOpacity
            style={styles.toggleButton}
            onPress={() => setIsRegister(!isRegister)}
          >
            <Text style={styles.toggleText}>
              {isRegister ? "Already have an account? " : "New here? "}
              <Text style={styles.toggleLinkText}>
                {isRegister ? "Sign In" : "Sign up"}
              </Text>
            </Text>
          </TouchableOpacity>
        </View>

        {/* Scrollable Content */}
        <ScrollView
          style={styles.scrollView}
          contentContainerStyle={styles.scrollContent}
          showsVerticalScrollIndicator={false}
          keyboardShouldPersistTaps="handled"
        >
          {/* Header */}

          <View style={styles.headerContainer}>
            <View style={styles.header}>
              <Text style={styles.welcomeText}>Welcome back 👋</Text>
              <Text style={styles.title}>
                {isRegister
                  ? `Register as ${userTypeLabel === "Artisan" ? "Artisan" : "User"}.`
                  : "Log in to continue exploring."}
              </Text>
            </View>

            {isRegister &&
              ((currentUserType === "User" && userRegisterStep === 1) ||
                (currentUserType === "Artisan" && agentRegisterStep === 1)) && (
                <StepIndicator currentStep={1} />
              )}
          </View>
          {/* Email Input */}
          <View style={styles.inputContainer}>
            <Text style={styles.label}>Email address</Text>
            <TextInput
              style={styles.input}
              placeholder="name@email.com"
              value={email}
              onChangeText={setEmail}
              keyboardType="email-address"
              autoCapitalize="none"
            />
          </View>

          {/* Password Input */}
          <View style={styles.inputContainer}>
            <Text style={styles.label}>Password</Text>
            <View style={styles.passwordContainer}>
              <TextInput
                style={styles.passwordInput}
                placeholder="Enter password"
                value={password}
                onChangeText={setPassword}
                secureTextEntry={!showPassword}
              />
              <TouchableOpacity
                onPress={() => setShowPassword(!showPassword)}
                style={styles.eyeIcon}
              >
                <Text style={styles.eyeText}>👁</Text>
              </TouchableOpacity>
            </View>
          </View>

          {/* Confirm Password (Registration Only) */}
          {isRegister && (
            <View style={styles.inputContainer}>
              <Text style={styles.label}>Confirm Password</Text>
              <View style={styles.passwordContainer}>
                <TextInput
                  style={styles.passwordInput}
                  placeholder="Re-enter password"
                  value={confirmPassword}
                  onChangeText={setConfirmPassword}
                  secureTextEntry={!showConfirmPassword}
                />
                <TouchableOpacity
                  onPress={() => setShowConfirmPassword(!showConfirmPassword)}
                  style={styles.eyeIcon}
                >
                  <Text style={styles.eyeText}>👁</Text>
                </TouchableOpacity>
              </View>
            </View>
          )}

          {/* User Registration - Step 1 */}
          {isRegister &&
            currentUserType === "User" &&
            userRegisterStep === 1 && (
              <>
                <View style={styles.photoSection}>
                  <View style={styles.photoContainer}>
                    <View style={styles.avatarLarge}>
                      <Text style={styles.avatarText}>📷</Text>
                    </View>
                    <TouchableOpacity style={styles.addPhotoButton}>
                      <Text style={styles.addPhotoIcon}>⊕</Text>
                    </TouchableOpacity>
                  </View>
                  <Text style={styles.photoLabel}>Add profile photo</Text>
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Full Name</Text>
                  <TextInput
                    style={styles.input}
                    placeholder="Enter your full name"
                    value={fullName}
                    onChangeText={setFullName}
                  />
                </View>

                <View style={styles.rowContainer}>
                  <View style={[styles.inputContainer, styles.halfWidth]}>
                    <Text style={styles.label}>First name</Text>
                    <TextInput
                      style={styles.input}
                      placeholder="Jude"
                      value={firstName}
                      onChangeText={setFirstName}
                    />
                  </View>
                  <View style={[styles.inputContainer, styles.halfWidth]}>
                    <Text style={styles.label}>Last name</Text>
                    <TextInput
                      style={styles.input}
                      placeholder="Mark"
                      value={lastName}
                      onChangeText={setLastName}
                    />
                  </View>
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Phone number</Text>
                  <TextInput
                    style={styles.input}
                    placeholder="+234 768 585 9595"
                    value={phoneNumber}
                    onChangeText={setPhoneNumber}
                    keyboardType="phone-pad"
                  />
                </View>
              </>
            )}

          {/* User Registration - Step 2: Service Preferences */}
          {isRegister &&
            currentUserType === "User" &&
            userRegisterStep === 2 && (
              <>
                <View style={styles.stepIndicator}>
                  <TouchableOpacity
                    onPress={() => setUserRegisterStep(1)}
                    style={styles.backButton}
                  >
                    <Text style={styles.backButtonText}>← Back</Text>
                  </TouchableOpacity>

                  {/* <Text style={styles.stepText}>
                Step 2 of 2 - Select Your Service Preferences
              </Text> */}
                  <View style={styles.stepTitleContainer}>
                    <View style={styles.stepTitle}>
                      <Text style={styles.stepSubtext}>
                        Tell us what you're looking for.
                      </Text>
                      <Text style={styles.stepText}>
                        Help us tailor your feeds!
                      </Text>
                    </View>

                    <StepIndicator currentStep={2} />
                  </View>
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>
                    What services are you interested in? (Select all that apply)
                  </Text>
                  <View style={styles.serviceGrid}>
                    {SERVICE_CATEGORIES.map((service) => (
                      <TouchableOpacity
                        key={service}
                        style={[
                          styles.serviceChip,
                          selectedServices.includes(service) &&
                            styles.serviceChipSelected,
                        ]}
                        onPress={() => toggleService(service)}
                      >
                        <Text
                          style={[
                            styles.serviceChipText,
                            selectedServices.includes(service) &&
                              styles.serviceChipTextSelected,
                          ]}
                        >
                          {service}
                        </Text>
                        {selectedServices.includes(service) && (
                          <Text style={styles.checkmark}>✓</Text>
                        )}
                      </TouchableOpacity>
                    ))}
                  </View>
                </View>
              </>
            )}

          {/* Agent Registration - Step 1 */}
          {isRegister &&
            currentUserType === "Artisan" &&
            agentRegisterStep === 1 && (
              <>
                <View style={styles.photoSection}>
                  <View style={styles.photoContainer}>
                    <View style={styles.avatarLarge}>
                      <Text style={styles.avatarText}>📷</Text>
                    </View>
                    <TouchableOpacity style={styles.addPhotoButton}>
                      <Text style={styles.addPhotoIcon}>⊕</Text>
                    </TouchableOpacity>
                  </View>
                  <Text style={styles.photoLabel}>Add profile photo</Text>
                </View>

                <View style={styles.rowContainer}>
                  <View style={[styles.inputContainer, styles.halfWidth]}>
                    <Text style={styles.label}>First name</Text>
                    <TextInput
                      style={styles.input}
                      placeholder="Jude"
                      value={firstName}
                      onChangeText={setFirstName}
                    />
                  </View>
                  <View style={[styles.inputContainer, styles.halfWidth]}>
                    <Text style={styles.label}>Last name</Text>
                    <TextInput
                      style={styles.input}
                      placeholder="Mark"
                      value={lastName}
                      onChangeText={setLastName}
                    />
                  </View>
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Phone number</Text>
                  <TextInput
                    style={styles.input}
                    placeholder="+234 768 585 9595"
                    value={phoneNumber}
                    onChangeText={setPhoneNumber}
                    keyboardType="phone-pad"
                  />
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Business Name</Text>
                  <TextInput
                    style={styles.input}
                    placeholder="Bontel Limited"
                    value={businessName}
                    onChangeText={setBusinessName}
                  />
                </View>
              </>
            )}

          {/* Agent Registration - Step 2 */}
          {isRegister &&
            currentUserType === "Artisan" &&
            agentRegisterStep === 2 && (
              <>
                <View style={styles.stepIndicator}>
                  <TouchableOpacity
                    onPress={() => setAgentRegisterStep(1)}
                    style={styles.backButton}
                  >
                    <Text style={styles.backButtonText}>← Back</Text>
                  </TouchableOpacity>

                  <View style={styles.stepTitleContainer}>
                    <View style={styles.stepTitle}>
                      <Text style={styles.stepSubtext}>
                        Let's help clients find you.
                      </Text>
                      <Text style={styles.stepText}>
                        Tell us about your first service!
                      </Text>
                    </View>

                    <StepIndicator currentStep={2} />
                  </View>
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Service Name *</Text>
                  <TextInput
                    style={styles.input}
                    placeholder="e.g., Home Plumbing Repair"
                    value={serviceName}
                    onChangeText={setServiceName}
                  />
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Service Category *</Text>
                  <TouchableOpacity
                    style={styles.input}
                    onPress={() => setShowCategoryPicker(!showCategoryPicker)}
                  >
                    <Text
                      style={
                        serviceCategory
                          ? styles.selectedText
                          : styles.placeholderText
                      }
                    >
                      {serviceCategory || "Select a category"}
                    </Text>
                  </TouchableOpacity>
                  {showCategoryPicker && (
                    <View style={styles.pickerContainer}>
                      {SERVICE_CATEGORIES.map((category) => (
                        <TouchableOpacity
                          key={category}
                          style={styles.pickerItem}
                          onPress={() => {
                            setServiceCategory(category);
                            setShowCategoryPicker(false);
                          }}
                        >
                          <Text style={styles.pickerItemText}>{category}</Text>
                        </TouchableOpacity>
                      ))}
                    </View>
                  )}
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Pricing Model *</Text>
                  <TouchableOpacity
                    style={styles.input}
                    onPress={() => setShowPricingPicker(!showPricingPicker)}
                  >
                    <Text
                      style={
                        pricingModel
                          ? styles.selectedText
                          : styles.placeholderText
                      }
                    >
                      {PRICING_MODELS.find((p) => p.value === pricingModel)
                        ?.label || "Select pricing model"}
                    </Text>
                  </TouchableOpacity>
                  {showPricingPicker && (
                    <View style={styles.pickerContainer}>
                      {PRICING_MODELS.map((model) => (
                        <TouchableOpacity
                          key={model.value}
                          style={styles.pickerItem}
                          onPress={() => {
                            setPricingModel(
                              model.value as "fixed" | "hourly" | "quote",
                            );
                            setShowPricingPicker(false);
                          }}
                        >
                          <Text style={styles.pickerItemText}>
                            {model.label}
                          </Text>
                        </TouchableOpacity>
                      ))}
                    </View>
                  )}
                </View>

                {pricingModel !== "quote" && (
                  <View style={styles.rowContainer}>
                    <View style={[styles.inputContainer, styles.halfWidth]}>
                      <Text style={styles.label}>
                        Min Price (₦) {pricingModel === "hourly" ? "/hr" : ""} *
                      </Text>
                      <TextInput
                        style={styles.input}
                        placeholder="5000"
                        value={minPrice}
                        onChangeText={setMinPrice}
                        keyboardType="numeric"
                      />
                    </View>
                    <View style={[styles.inputContainer, styles.halfWidth]}>
                      <Text style={styles.label}>
                        Max Price (₦) {pricingModel === "hourly" ? "/hr" : ""}
                      </Text>
                      <TextInput
                        style={styles.input}
                        placeholder="15000"
                        value={maxPrice}
                        onChangeText={setMaxPrice}
                        keyboardType="numeric"
                      />
                    </View>
                  </View>
                )}

                {pricingModel === "quote" && (
                  <View style={styles.infoBox}>
                    <Text style={styles.infoText}>
                      💡 Quote-based pricing means you'll provide custom quotes
                      for each job request
                    </Text>
                  </View>
                )}

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Availability *</Text>
                  <TextInput
                    style={styles.input}
                    placeholder="e.g., Mon-Fri 9AM-5PM, Weekends by appointment"
                    value={availability}
                    onChangeText={setAvailability}
                    multiline
                    numberOfLines={2}
                  />
                </View>

                <View style={styles.inputContainer}>
                  <Text style={styles.label}>Service Notes (Optional)</Text>
                  <TextInput
                    style={[styles.input, styles.textArea]}
                    placeholder="Additional details about your service, requirements, or special offers..."
                    value={serviceNotes}
                    onChangeText={setServiceNotes}
                    multiline
                    numberOfLines={4}
                  />
                </View>
              </>
            )}

          {/* Forgot Password (Only for login) */}
          {!isRegister && (
            <TouchableOpacity style={styles.forgotPassword}>
              <Text style={styles.forgotPasswordText}>Forgot password?</Text>
            </TouchableOpacity>
          )}

          {/* Terms and Privacy */}
          {isRegister ? (
            (currentUserType === "Artisan" && agentRegisterStep === 1) ||
            (currentUserType === "User" && userRegisterStep === 1) ? null : (
              <Text style={styles.termsText}>
                By continuing, you agree to our{" "}
                <Text style={styles.linkText}>Terms of Service</Text> and{" "}
                <Text style={styles.linkText}>Privacy Policy</Text>.
              </Text>
            )
          ) : (
            <Text style={styles.termsText}>
              By continuing, you agree to our{" "}
              <Text style={styles.linkText}>Terms of Service</Text> and{" "}
              <Text style={styles.linkText}>Privacy Policy</Text>.
            </Text>
          )}

          {/* Login/Sign Up Button */}
          <TouchableOpacity
            style={styles.button}
            onPress={handleAuth}
            disabled={isLoading}
          >
            <Text style={styles.buttonText}>
              {isLoading
                ? "Loading..."
                : isRegister
                  ? (currentUserType === "Artisan" &&
                      agentRegisterStep === 1) ||
                    (currentUserType === "User" && userRegisterStep === 1)
                    ? "Next Step"
                    : "Sign Up"
                  : "Log in"}
            </Text>
          </TouchableOpacity>

          {/* Divider - Only show for login */}
          {!isRegister && (
            <>
              <View style={styles.divider}>
                <View style={styles.dividerLine} />
                <Text style={styles.dividerText}>Or Continue with</Text>
                <View style={styles.dividerLine} />
              </View>

              {/* Switch User Type */}
              <TouchableOpacity
                onPress={() =>
                  setCurrentUserType((prev) =>
                    prev === "User" ? "Artisan" : "User",
                  )
                }
                style={styles.switchButton}
              >
                <Image
                  source={require("../assets/images/switch.png")}
                  style={styles.switchIcon}
                />
                <Text style={styles.switchText}>
                  Continue as {userTypeLabel === "Artisan" ? "User" : "Artisan"}
                </Text>
              </TouchableOpacity>

              {/* Google Sign In */}
              <TouchableOpacity style={styles.googleButton}>
                <Text style={styles.googleIcon}>G</Text>
                <Text style={styles.googleText}>Sign in with Google</Text>
              </TouchableOpacity>
            </>
          )}

          {/* Bottom padding for scroll */}
          <View style={styles.bottomPadding} />
        </ScrollView>
      </KeyboardAvoidingView>
    </>
  );
}

/* ---------------------------
   Styles
---------------------------- */
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "white",
  },
  fixedHeader: {
    paddingHorizontal: 20,
    paddingTop: 60,
    paddingBottom: 12,
    backgroundColor: "white",
    borderBottomWidth: 1,
    borderBottomColor: "#f0f0f0",
    alignItems: "flex-end",
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    paddingHorizontal: 20,
    paddingTop: 20,
  },
  headerContainer: {
    display: "flex",
    flexDirection: "row",
    justifyContent: "space-between",
    // gap: 1,
    marginBottom: 32,
  },
  header: {
    // marginBottom: 32,
  },
  welcomeText: {
    fontSize: 16,
    color: "#666",
    marginBottom: 4,
  },
  title: {
    fontSize: 26,
    fontWeight: "bold",
    color: "#1a1a1a",
    lineHeight: 34,
  },
  inputContainer: {
    marginBottom: 20,
  },
  label: {
    fontSize: 14,
    fontWeight: "500",
    color: "#1a1a1a",
    marginBottom: 8,
  },
  input: {
    borderWidth: 1,
    borderColor: "#e0e0e0",
    padding: 14,
    borderRadius: 8,
    fontSize: 16,
    backgroundColor: "white",
  },
  textArea: {
    height: 100,
    textAlignVertical: "top",
  },
  passwordContainer: {
    flexDirection: "row",
    alignItems: "center",
    borderWidth: 1,
    borderColor: "#e0e0e0",
    borderRadius: 8,
    backgroundColor: "white",
  },
  passwordInput: {
    flex: 1,
    padding: 14,
    fontSize: 16,
  },
  eyeIcon: {
    padding: 14,
  },
  eyeText: {
    fontSize: 18,
  },
  forgotPassword: {
    alignSelf: "flex-start",
    marginBottom: 16,
  },
  forgotPasswordText: {
    color: "#0ea5e9",
    fontSize: 14,
    fontWeight: "500",
  },
  termsText: {
    fontSize: 13,
    color: "#666",
    marginBottom: 20,
    lineHeight: 18,
  },
  linkText: {
    color: "#0ea5e9",
    fontWeight: "500",
  },
  button: {
    backgroundColor: "#0ea5e9",
    padding: 16,
    borderRadius: 8,
    alignItems: "center",
    marginBottom: 20,
  },
  buttonText: {
    color: "white",
    fontSize: 16,
    fontWeight: "600",
  },
  divider: {
    flexDirection: "row",
    alignItems: "center",
    marginVertical: 20,
  },
  dividerLine: {
    flex: 1,
    height: 1,
    backgroundColor: "#e0e0e0",
  },
  dividerText: {
    marginHorizontal: 12,
    fontSize: 14,
    color: "#999",
  },
  googleButton: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    padding: 14,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#e0e0e0",
    backgroundColor: "white",
    marginBottom: 20,
  },
  googleIcon: {
    fontSize: 20,
    marginRight: 10,
    fontWeight: "bold",
  },
  googleText: {
    fontSize: 15,
    color: "#1a1a1a",
    fontWeight: "500",
  },
  toggleButton: {
    padding: 4,
  },
  toggleText: {
    fontSize: 16,
    color: "#666",
  },
  toggleLinkText: {
    color: "#0ea5e9",
    fontWeight: "600",
  },
  switchButton: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    paddingVertical: 12,
    marginBottom: 12,
  },
  switchIcon: {
    width: 18,
    height: 18,
    marginRight: 8,
  },
  switchText: {
    fontSize: 16,
    fontWeight: "500",
  },
  photoSection: {
    alignItems: "center",
    marginBottom: 24,
  },
  photoContainer: {
    position: "relative",
    marginBottom: 8,
  },
  avatarLarge: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: "#7c5ce0",
    alignItems: "center",
    justifyContent: "center",
  },
  avatarText: {
    fontSize: 32,
  },
  addPhotoButton: {
    position: "absolute",
    bottom: 0,
    right: 0,
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: "#0ea5e9",
    alignItems: "center",
    justifyContent: "center",
    borderWidth: 3,
    borderColor: "white",
  },
  addPhotoIcon: {
    color: "white",
    fontSize: 16,
    fontWeight: "bold",
  },
  photoLabel: {
    fontSize: 14,
    color: "#1a1a1a",
    fontWeight: "500",
  },
  rowContainer: {
    flexDirection: "row",
    justifyContent: "space-between",
    gap: 12,
  },
  halfWidth: {
    flex: 1,
  },
  stepIndicator: {
    marginBottom: 24,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: "#e0e0e0",
  },
  stepTitleContainer: {
    display: "flex",
    flexDirection: "row",
    justifyContent: "space-between",
    gap: 1,
    marginTop: 10,
  },
  stepTitle: {
    display: "flex",
    flexDirection: "column",
    gap: 4,
    // marginTop: 10,
  },
  stepText: {
    fontSize: 20,
    fontWeight: "600",
    color: "#1a1a1a",
    // marginBottom: 8,
  },
  stepSubtext: {
    fontSize: 14,
    fontWeight: "600",
    color: "#979797",
    // marginBottom: 8,
  },
  backButton: {
    alignSelf: "flex-start",
  },
  backButtonText: {
    color: "#0ea5e9",
    fontSize: 14,
    fontWeight: "500",
  },
  bottomPadding: {
    height: 40,
  },
  pickerContainer: {
    borderWidth: 1,
    borderColor: "#e0e0e0",
    borderRadius: 8,
    marginTop: 8,
    backgroundColor: "white",
    maxHeight: 200,
  },
  pickerItem: {
    padding: 14,
    borderBottomWidth: 1,
    borderBottomColor: "#f0f0f0",
  },
  pickerItemText: {
    fontSize: 16,
    color: "#1a1a1a",
  },
  selectedText: {
    fontSize: 16,
    color: "#1a1a1a",
  },
  placeholderText: {
    fontSize: 16,
    color: "#999",
  },
  infoBox: {
    backgroundColor: "#f0f9ff",
    padding: 12,
    borderRadius: 8,
    marginBottom: 20,
    borderLeftWidth: 3,
    borderLeftColor: "#0ea5e9",
  },
  infoText: {
    fontSize: 14,
    color: "#0369a1",
    lineHeight: 20,
  },
  serviceGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 10,
    marginTop: 8,
  },
  serviceChip: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 10,
    paddingHorizontal: 16,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: "#e0e0e0",
    backgroundColor: "white",
  },
  serviceChipSelected: {
    backgroundColor: "#0ea5e9",
    borderColor: "#0ea5e9",
  },
  serviceChipText: {
    fontSize: 14,
    color: "#1a1a1a",
    fontWeight: "500",
  },
  serviceChipTextSelected: {
    color: "white",
  },
  checkmark: {
    marginLeft: 6,
    color: "white",
    fontSize: 14,
    fontWeight: "bold",
  },
  otpContainer: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginVertical: 32,
    paddingHorizontal: 10,
  },
  otpInput: {
    width: 48,
    height: 56,
    borderWidth: 2,
    borderColor: "#e0e0e0",
    borderRadius: 12,
    fontSize: 24,
    fontWeight: "600",
    color: "#1a1a1a",
  },
  resendButton: {
    alignSelf: "center",
    marginBottom: 24,
  },
  resendText: {
    fontSize: 14,
    color: "#666",
  },
});
