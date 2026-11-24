plugins {
    id("com.android.application") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "2.1.0"
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.0"
}

android {
    namespace = "io.github.burtvadr.rba"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.burtvadr.rba"
        // API 28 is the baseline for a security-focused new project: modern
        // Keystore facilities, and StrongBox APIs become available.
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            // A debug build must never be shipped as an authenticator: the
            // signing key would be attacker-known. Release builds use the normal
            // Android release process.
            applicationIdSuffix = ".debug"
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }
}

dependencies {
    // The protocol is implemented in Kotlin in a sibling module, independently
    // of the Rust implementation and validated against the shared vectors.
    implementation(project(":protocol"))

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.ui:ui-tooling-preview")

    // BiometricPrompt and the authenticator-class checks that make a strong
    // biometric a requirement rather than a preference.
    implementation("androidx.biometric:biometric:1.1.0")
    // BiometricPrompt requires a FragmentActivity host.
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

// Build the same portable enrollment crate used by the host. cargo-ndk uses
// the Android NDK, not the build machine's native compiler.
val enrollmentManifest = rootProject.file("../crates/rba-enrollment-jni/Cargo.toml")
val enrollmentLibs = layout.buildDirectory.dir("generated/enrollment/jniLibs")
val buildEnrollmentNative by tasks.registering(Exec::class) {
    workingDir(rootProject.file(".."))
    inputs.dir(rootProject.file("../crates/rba-enrollment"))
    inputs.dir(rootProject.file("../crates/rba-enrollment-jni"))
    outputs.dir(enrollmentLibs)
    commandLine("cargo", "ndk", "-p", "28", "-t", "arm64-v8a", "-t", "armeabi-v7a", "-t", "x86_64",
        "-o", enrollmentLibs.get().asFile.absolutePath, "build", "--release", "--manifest-path", enrollmentManifest.absolutePath)
}
android.sourceSets.getByName("main").jniLibs.srcDir(enrollmentLibs)
tasks.named("preBuild").configure { dependsOn(buildEnrollmentNative) }
