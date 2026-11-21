import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// ── Version ──────────────────────────────────────────────────────────────────
// The repo-root VERSION file is authoritative. `acowork.version` (a Gradle
// property) and ACOWORK_VERSION (an environment variable) override it, so CI
// can stamp a tag-derived version without editing a file.
// `rootProject` is `apps/android`, so the repository root is two levels up.
val repoRootDir = rootProject.file("../..")

val versionText = (findProperty("acowork.version") as String?)
    ?: System.getenv("ACOWORK_VERSION")
    ?: repoRootDir.resolve("VERSION").takeIf { it.isFile }?.readText()?.trim()
    ?: "0.1.0"

// A release tag carries a "v" prefix ("v0.1.0"); the APK's versionName must
// not, because it is what the device's package manager compares.
//
// NOTE the name: inside `defaultConfig { }` the identifier `versionName`
// resolves to the DSL property being assigned, not to a variable of the same
// name, so a variable called `versionName` would silently assign itself.
val appVersionName = versionText.removePrefix("v").trim()

val versionParts = appVersionName.split('.')
require(versionParts.size >= 3) { "ACoworkNode version must be MAJOR.MINOR.PATCH, got '$appVersionName'" }
val versionMajor = versionParts[0].toInt()
val versionMinor = versionParts[1].toInt()
val versionPatch = versionParts[2].substringBefore('-').toInt()

// Monotonic versionCode: Play rejects an upload whose code does not increase.
// major*1_000_000 + minor*1_000 + patch keeps room for 999 patches per minor.
val versionCodeValue = versionMajor * 1_000_000 + versionMinor * 1_000 + versionPatch

// ── Signing ──────────────────────────────────────────────────────────────────
// The keystore NEVER lives in the repository. It is read from a local path
// (gradle property `acowork.keystoreFile`, or env ACOWORK_KEYSTORE_FILE) and
// the passwords come from the environment, so CI can inject them as secrets.
//
// When any piece is missing the release build stays UNSIGNED instead of
// failing: an unsigned release APK is still useful for local smoke tests, and
// a release workflow that silently produced an unsigned artifact would be
// worse than one that says so.
val signingPropsFile = repoRootDir.resolve("keystore.properties")
val signingProps = Properties().apply {
    if (signingPropsFile.isFile) signingPropsFile.inputStream().use { load(it) }
}

fun signingValue(propName: String, envName: String): String? {
    val v = (project.findProperty(propName) as String?)?.takeIf { it.isNotBlank() }
        ?: signingProps.getProperty(propName)?.takeIf { it.isNotBlank() }
        ?: System.getenv(envName)?.takeIf { it.isNotBlank() }
    return v
}

// NOTE the names: inside `create("release") { ... }` the receiver is a
// SigningConfig, which has properties named storeFile / storePassword /
// keyAlias / keyPassword. A variable with the same name would make the
// right-hand side resolve to the receiver's own (unset) property instead of
// our value, and the build would fail with a confusing "missing required
// property" error.
val signingKeystoreFile = signingValue("acowork.keystoreFile", "ACOWORK_KEYSTORE_FILE")
val signingKeystorePassword = signingValue("acowork.keystorePassword", "ACOWORK_KEYSTORE_PASSWORD")
val signingKeyAlias = signingValue("acowork.keyAlias", "ACOWORK_KEY_ALIAS")
val signingKeyPassword = signingValue("acowork.keyPassword", "ACOWORK_KEY_PASSWORD")

val hasSigningMaterial = listOf(
    signingKeystoreFile, signingKeystorePassword, signingKeyAlias, signingKeyPassword
).all { !it.isNullOrBlank() }

android {
    namespace = "com.acowork.androidhost"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.acowork.androidhost"
        minSdk = 26
        targetSdk = 35
        versionCode = versionCodeValue
        versionName = appVersionName
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        if (hasSigningMaterial) {
            create("release") {
                // `file()` resolves against the app module, but the keystore
                // path comes from a repo-root-relative or absolute location.
                // Resolve it against the repo root so both work.
                // `hasSigningMaterial` proves these are non-null, but the
                // compiler cannot see that through the list check.
                val store = signingKeystoreFile!!
                storeFile = file(
                    if (File(store).isAbsolute) store
                    else repoRootDir.resolve(store).path
                )
                storePassword = signingKeystorePassword
                keyAlias = signingKeyAlias
                keyPassword = signingKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (hasSigningMaterial) {
                signingConfig = signingConfigs.getByName("release")
            }
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

    testImplementation("junit:junit:4.13.2")
}

// Build libacowork_android_ffi.so into jniLibs before assembling.
val cargoTarget = "aarch64-linux-android"
val jniOut = layout.projectDirectory.dir("src/main/jniLibs/arm64-v8a")
val workspaceRoot = layout.projectDirectory.dir("../../..")

// The NDK toolchain env must be exported for the whole cargo invocation, not
// just the linker: `zstd-sys` and friends compile C sources with cc-rs, and
// without CC/CFLAGS pointing at the NDK sysroot they fail with
// "string.h file not found". Setting the linker alone is not enough.
val ndkVersion = "26.1.10909125"
val ndkHome = System.getenv("ANDROID_NDK_HOME")
    ?: (System.getenv("ANDROID_HOME")?.let { "$it/ndk/$ndkVersion" })
    ?: ""
val ndkHostTag = when {
    System.getProperty("os.name").startsWith("Windows") -> "windows-x86_64"
    System.getProperty("os.name").startsWith("Mac") -> "darwin-x86_64"
    else -> "linux-x86_64"
}
val ndkPrebuilt = if (ndkHome.isNotBlank()) "$ndkHome/toolchains/llvm/prebuilt/$ndkHostTag" else ""
val ndkIsWindows = ndkHostTag.startsWith("windows")
// The NDK ships a `.cmd` shim on Windows and a plain executable elsewhere.
val clangName = if (ndkIsWindows) "aarch64-linux-android26-clang.cmd" else "aarch64-linux-android26-clang"
val clangxxName = if (ndkIsWindows) "aarch64-linux-android26-clang++.cmd" else "aarch64-linux-android26-clang++"
val arName = if (ndkIsWindows) "llvm-ar.exe" else "llvm-ar"

tasks.register<Exec>("cargoNdkArm64") {
    group = "build"
    description = "Cross-compile host FFI and engine CLI for arm64-v8a"
    workingDir = workspaceRoot.asFile
    environment("ANDROID_NDK_HOME", ndkHome)
    if (ndkPrebuilt.isNotBlank()) {
        environment("CC_aarch64_linux_android", "$ndkPrebuilt/bin/$clangName")
        environment("CXX_aarch64_linux_android", "$ndkPrebuilt/bin/$clangxxName")
        environment("AR_aarch64_linux_android", "$ndkPrebuilt/bin/$arName")
        environment("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", "$ndkPrebuilt/bin/$clangName")
        environment("CFLAGS_aarch64_linux_android", "--sysroot=$ndkPrebuilt/sysroot")
        environment("CXXFLAGS_aarch64_linux_android", "--sysroot=$ndkPrebuilt/sysroot")
    }
    commandLine(
        "cargo", "build",
        "-p", "acowork-android-ffi",
        "-p", "acowork-android-cli",
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
        if (!engineSrc.exists()) {
            throw GradleException("missing $engineSrc — android device tools will not appear until the engine is rebuilt")
        }
        engineSrc.copyTo(engineDst, overwrite = true)
    }
}

// The packaged POSIX shell (mksh R57) that the host uses when SELinux forbids
// untrusted_app from exec'ing /system/bin/sh. It is a third-party binary, so
// it is built from a pinned upstream commit by dev/android/build_ash.sh and
// copied in here — never committed, exactly like the Rust artifacts above.
tasks.register("copyPackagedShell") {
    group = "build"
    description = "Copy the prebuilt libacowork_ash.so into jniLibs"
    val ashSrc = layout.projectDirectory.dir("../../../build/android/libacowork_ash.so")
    val ashDst = jniOut.dir("libacowork_ash.so")
    inputs.file(ashSrc).optional()
    outputs.file(ashDst)
    doLast {
        if (!ashSrc.asFile.isFile) {
            throw GradleException(
                "missing ${ashSrc.asFile} — run dev/android/build_ash.sh to build the packaged shell"
            )
        }
        ashSrc.asFile.copyTo(ashDst.asFile, overwrite = true)
    }
}

tasks.named("preBuild") {
    // Optional: run when ANDROID_NDK_HOME / linker is ready. Disable auto-dep if
    // developing UI-only; invoke `./gradlew cargoNdkArm64` explicitly then.
    // dependsOn("cargoNdkArm64")
}
