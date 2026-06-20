plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val rustJniLibsDir = layout.buildDirectory.dir("generated/jniLibs/rust")

android {
    namespace = "dev.slt.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.slt.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
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
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDir(rustJniLibsDir)
        }
    }
}

val buildRustNative by tasks.registering(Exec::class) {
    val workspaceDir = rootProject.layout.projectDirectory.asFile.parentFile
    val androidNdkHome = providers.environmentVariable("ANDROID_NDK_HOME")
        .orElse(providers.environmentVariable("ANDROID_NDK_ROOT"))

    group = "build"
    description = "Build Rust Android shared libraries for SLT."
    workingDir = workspaceDir

    inputs.property("androidNdkHome", androidNdkHome)
    inputs.file(workspaceDir.resolve("Cargo.lock"))
    inputs.file(workspaceDir.resolve("Cargo.toml"))
    inputs.file(workspaceDir.resolve("slt-client/Cargo.toml"))
    inputs.dir(workspaceDir.resolve("slt-client/src"))
    inputs.file(workspaceDir.resolve("slt-core/Cargo.toml"))
    inputs.dir(workspaceDir.resolve("slt-core/src"))
    outputs.dir(rustJniLibsDir)

    commandLine(
        "cargo",
        "ndk",
        "-t",
        "arm64-v8a",
        "-t",
        "x86_64",
        "-o",
        rustJniLibsDir.get().asFile.absolutePath,
        "build",
        "-p",
        "slt-client",
        "--release",
        "--lib",
    )

    doLast {
        val ndkDir = androidNdkHome.orNull
            ?: error("ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set")
        val prebuiltDir = file(ndkDir)
            .resolve("toolchains/llvm/prebuilt")
            .listFiles()
            ?.singleOrNull { it.isDirectory && it.resolve("sysroot").isDirectory }
            ?: error("could not find LLVM prebuilt sysroot in Android NDK: $ndkDir")
        val sysrootLibDir = prebuiltDir.resolve("sysroot/usr/lib")
        val libcxxTargets = mapOf(
            "arm64-v8a" to "aarch64-linux-android",
            "x86_64" to "x86_64-linux-android",
        )

        libcxxTargets.forEach { (abi, target) ->
            copy {
                from(sysrootLibDir.resolve("$target/libc++_shared.so"))
                into(rustJniLibsDir.get().asFile.resolve(abi))
            }
        }
    }
}

tasks.named("preBuild") {
    dependsOn(buildRustNative)
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.06.00")

    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
