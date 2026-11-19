plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.acowork.androidhost"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.acowork.androidhost"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
        debug {
            isDebuggable = true
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
        viewBinding = true
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}

// Build libacowork_android_ffi.so into jniLibs before assembling.
val cargoTarget = "aarch64-linux-android"
val jniOut = layout.projectDirectory.dir("src/main/jniLibs/arm64-v8a")
val workspaceRoot = layout.projectDirectory.dir("../../..")

tasks.register<Exec>("cargoNdkArm64") {
    group = "build"
    description = "Cross-compile acowork-android-ffi for arm64-v8a"
    workingDir = workspaceRoot.asFile
    environment("ANDROID_NDK_HOME", System.getenv("ANDROID_NDK_HOME")
        ?: (System.getenv("ANDROID_HOME")?.let { "$it/ndk/26.1.10909125" } ?: ""))
    commandLine(
        "cargo", "build",
        "-p", "acowork-android-ffi",
        "--release",
        "--target", cargoTarget,
    )
    doLast {
        jniOut.asFile.mkdirs()
        val ffi = workspaceRoot.asFile.resolve(
            "target/$cargoTarget/release/libacowork_android_ffi.so",
        )
        if (!ffi.exists()) {
            throw GradleException("missing $ffi — install aarch64-linux-android target + NDK linker")
        }
        ffi.copyTo(jniOut.asFile.resolve("libacowork_android_ffi.so"), overwrite = true)
        // CLI binary packaged as lib*.so so AGP extracts it with +x into nativeLibraryDir.
        val engineSrc = workspaceRoot.asFile.resolve(
            "target/$cargoTarget/release/acowork-android",
        )
        val engineDst = jniOut.asFile.resolve("libacowork_engine.so")
        if (engineSrc.exists()) {
            engineSrc.copyTo(engineDst, overwrite = true)
        } else {
            logger.warn("engine binary missing at $engineSrc — start/stop agents will fail until built")
        }
    }
}

tasks.named("preBuild") {
    // Optional: run when ANDROID_NDK_HOME / linker is ready. Disable auto-dep if
    // developing UI-only; invoke `./gradlew cargoNdkArm64` explicitly then.
    // dependsOn("cargoNdkArm64")
}
