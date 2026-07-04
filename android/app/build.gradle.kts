plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("app.cash.licensee")
}

val workspaceDir = rootProject.layout.projectDirectory.asFile.parentFile
val androidNdkHome = providers.environmentVariable("ANDROID_NDK_HOME")
    .orElse(providers.environmentVariable("ANDROID_NDK_ROOT"))
val debugAndroidAbis = listOf("arm64-v8a", "x86_64")
val releaseAndroidAbis = listOf("arm64-v8a")
val androidLibcxxTargets = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "x86_64" to "x86_64-linux-android",
)
val rustAndroidBuildTypes = mapOf(
    "debug" to debugAndroidAbis,
    "release" to releaseAndroidAbis,
)

fun variantTaskSuffix(variantName: String): String =
    variantName.replaceFirstChar { it.uppercase() }

fun rustJniLibsDir(variantName: String) =
    layout.buildDirectory.dir("generated/jniLibs/rust/$variantName")

fun generatedUniFfiDir(variantName: String) =
    layout.buildDirectory.dir("generated/source/uniffi/$variantName/kotlin")

fun pinnedUniFfiVersion(workspaceDir: File): String {
    val cargoToml = workspaceDir.resolve("Cargo.toml").readText()
    return Regex("""(?m)^\s*uniffi\s*=\s*\{[^}]*version\s*=\s*"=([^"]+)"""")
        .find(cargoToml)
        ?.groupValues
        ?.get(1)
        ?: error("could not find exact pinned uniffi version in workspace Cargo.toml")
}

// The app version's single source of truth is `[workspace.package] version` in
// the workspace Cargo.toml; gradle reads it here so the APK versionName agrees
// with the Rust crate. The package version is the only line-anchored
// `version = "..."` key in Cargo.toml (dependency versions nest under their
// crate key, e.g. `clap = { version = ... }`), so this singles it out.
fun cargoWorkspaceVersion(workspaceDir: File): String {
    val cargoToml = workspaceDir.resolve("Cargo.toml").readText()
    return Regex("""(?m)^\s*version\s*=\s*"([^"]+)"""")
        .find(cargoToml)
        ?.groupValues
        ?.get(1)
        ?: error("could not find workspace package version in workspace Cargo.toml")
}

fun copyAndroidLibcxxShared(ndkDir: String, jniLibsDir: File, abis: List<String>) {
    val prebuiltDir = file(ndkDir)
        .resolve("toolchains/llvm/prebuilt")
        .listFiles()
        ?.singleOrNull { it.isDirectory && it.resolve("sysroot").isDirectory }
        ?: error("could not find LLVM prebuilt sysroot in Android NDK: $ndkDir")
    val sysrootLibDir = prebuiltDir.resolve("sysroot/usr/lib")

    abis.forEach { abi ->
        val target = androidLibcxxTargets.getValue(abi)
        val abiDir = jniLibsDir.resolve(abi)
        val existingLibcxx = abiDir.resolve("libc++_shared.so")
        if (existingLibcxx.exists() && !existingLibcxx.delete()) {
            error("could not replace generated JNI lib: $existingLibcxx")
        }
        copy {
            from(sysrootLibDir.resolve("$target/libc++_shared.so"))
            into(abiDir)
        }
    }
}

val appVersion = cargoWorkspaceVersion(workspaceDir)
val gitSha = runCatching {
    providers.exec {
        commandLine("git", "rev-parse", "--short", "HEAD")
    }.standardOutput.asText.get().trim()
}.getOrDefault("").ifBlank { "unknown" }

android {
    namespace = "dev.slt.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.slt.android"
        minSdk = 33
        targetSdk = 35
        versionCode = 1
        versionName = appVersion
        buildConfigField("String", "GIT_SHA", "\"$gitSha\"")
    }

    buildTypes {
        debug {
            ndk {
                abiFilters += debugAndroidAbis
            }
        }
        release {
            ndk {
                abiFilters += releaseAndroidAbis
            }
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

    sourceSets {
        rustAndroidBuildTypes.keys.forEach { variantName ->
            getByName(variantName) {
                jniLibs.srcDir(rustJniLibsDir(variantName))
                java.srcDir(generatedUniFfiDir(variantName))
            }
        }
    }

    lint {
        warningsAsErrors = true
        enable += setOf(
            "ComposableLambdaParameterNaming",
            "ComposableLambdaParameterPosition",
            "StopShip",
        )

        // API 36 is not installed in the local SDK yet; keep these visible in
        // reports without making normal lint fail.
        informational += setOf(
            "GradleDependency",
            "OldTargetApi",
        )
        disable += "ChromeOsAbiSupport"
    }
}

licensee {
    allow("Apache-2.0")
    bundleAndroidAsset = true
}

fun registerBuildRustNativeTask(variantName: String, abis: List<String>) =
    tasks.register<Exec>("buildRustNative${variantTaskSuffix(variantName)}") {
        val outputDir = rustJniLibsDir(variantName)
        val cargoArgs = mutableListOf(
            "cargo",
            "ndk",
        )

        abis.forEach { abi ->
            cargoArgs += listOf("-t", abi)
        }

        cargoArgs += listOf(
            "-o",
            outputDir.get().asFile.absolutePath,
            "build",
            "-p",
            "slt-client",
        )

        if (variantName == "release") {
            cargoArgs += "--release"
        }

        cargoArgs += "--lib"

        group = "build"
        description = "Build $variantName Rust Android shared libraries for SLT."
        workingDir = workspaceDir

        inputs.property("androidNdkHome", androidNdkHome)
        inputs.property("abis", abis)
        inputs.property("profile", if (variantName == "release") "release" else "dev")
        inputs.file(workspaceDir.resolve("Cargo.lock"))
        inputs.file(workspaceDir.resolve("Cargo.toml"))
        inputs.file(workspaceDir.resolve("slt-client/Cargo.toml"))
        inputs.file(workspaceDir.resolve("slt-client/uniffi.toml"))
        inputs.dir(workspaceDir.resolve("slt-client/src"))
        inputs.file(workspaceDir.resolve("slt-core/Cargo.toml"))
        inputs.dir(workspaceDir.resolve("slt-core/src"))
        outputs.dir(outputDir)

        doFirst {
            outputDir.get().asFile.deleteRecursively()
        }

        commandLine(cargoArgs)

        doLast {
            val ndkDir = androidNdkHome.orNull
                ?: error("ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set")
            copyAndroidLibcxxShared(ndkDir, outputDir.get().asFile, abis)
        }
    }

val checkUniFfiBindgenVersion by tasks.registering {
    group = "verification"
    description = "Check that uniffi-bindgen matches the pinned Rust UniFFI crate."

    inputs.file(workspaceDir.resolve("Cargo.toml"))

    doLast {
        val expectedVersion = pinnedUniFfiVersion(workspaceDir)
        val process = ProcessBuilder("uniffi-bindgen", "--version")
            .redirectErrorStream(true)
            .start()
        val versionText = process.inputStream.bufferedReader().use { it.readText() }.trim()
        val exitCode = process.waitFor()
        if (exitCode != 0) {
            error("uniffi-bindgen --version failed with exit code $exitCode: $versionText")
        }
        val actualVersion = Regex("""\buniffi-bindgen\s+(\S+)""")
            .find(versionText)
            ?.groupValues
            ?.get(1)
            ?: error("could not parse uniffi-bindgen version from: $versionText")

        if (actualVersion != expectedVersion) {
            error(
                "uniffi-bindgen $actualVersion does not match pinned Rust uniffi $expectedVersion. " +
                    "Install matching bindgen or update both versions together.",
            )
        }
    }
}

fun registerGenerateUniFfiBindingsTask(
    variantName: String,
    buildRustNative: TaskProvider<Exec>,
) = tasks.register<Exec>("generateUniFfiBindings${variantTaskSuffix(variantName)}") {
    val generatedDir = generatedUniFfiDir(variantName)
    val bindingLibrary = rustJniLibsDir(variantName).map { it.file("arm64-v8a/libslt_client.so") }

    group = "build"
    description = "Generate $variantName Kotlin bindings for the SLT Rust UniFFI API."
    workingDir = workspaceDir

    dependsOn(buildRustNative)
    dependsOn(checkUniFfiBindgenVersion)

    inputs.file(bindingLibrary)
    inputs.file(workspaceDir.resolve("Cargo.lock"))
    inputs.file(workspaceDir.resolve("Cargo.toml"))
    inputs.file(workspaceDir.resolve("slt-client/Cargo.toml"))
    inputs.file(workspaceDir.resolve("slt-client/uniffi.toml"))
    inputs.dir(workspaceDir.resolve("slt-client/src"))
    outputs.dir(generatedDir)

    doFirst {
        generatedDir.get().asFile.deleteRecursively()
    }

    commandLine(
        "uniffi-bindgen",
        "generate",
        "--library",
        bindingLibrary.get().asFile.absolutePath,
        "--language",
        "kotlin",
        "--out-dir",
        generatedDir.get().asFile.absolutePath,
    )
}

val generateUniFfiBindingTasks = rustAndroidBuildTypes.mapValues { (variantName, abis) ->
    val buildRustNative = registerBuildRustNativeTask(variantName, abis)
    registerGenerateUniFfiBindingsTask(variantName, buildRustNative)
}

generateUniFfiBindingTasks.forEach { (variantName, generateUniFfiBindings) ->
    val preBuildTaskName = "pre${variantTaskSuffix(variantName)}Build"
    tasks.configureEach {
        if (name == preBuildTaskName) {
            dependsOn(generateUniFfiBindings)
        }
    }
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    generateUniFfiBindingTasks.forEach { (variantName, generateUniFfiBindings) ->
        if (name.contains(variantTaskSuffix(variantName))) {
            dependsOn(generateUniFfiBindings)
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.06.00")

    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260522")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
