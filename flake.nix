{
  description = "TLS playground";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    systems.url = "github:nix-systems/default";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      systems = import inputs.systems;

      perSystem = {system, ...}: let
        # A nixpkgs instance with config that flake-parts' default pkgs doesn't
        # expose: the Android SDK/NDK are unfree (allowUnfree) and the composed
        # SDK build requires explicit license acceptance.
        pkgs = import inputs.nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
          };
        };

        # Auto-patchelf'd Android SDK for headless Gradle builds and JVM unit
        # tests. Emulator / system-images / NDK are excluded deliberately:
        # unit tests are JVM-only (no device), and the Rust `.so` is
        # cross-compiled separately with `cargo ndk` using the NDK below.
        # Gradle/java/cargo-ndk come from PATH; this shell provides only the
        # NixOS-irreplaceable bits.
        androidSdk = pkgs.androidenv.composeAndroidPackages {
          platformVersions = ["34" "35"];
          buildToolsVersions = ["34.0.0" "35.0.0"];
          includeEmulator = false;
          includeSystemImages = false;
          includeNDK = false;
          includeCmake = false;
          includeSources = false;
        };

        # Auto-patchelf'd NDK (its clang runs on NixOS) for `cargo ndk`.
        ndk = pkgs.androidenv.androidPkgs.ndk-bundle;
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            # Rust host build/test (boringssl/quiche via the `cc` crate + bindgen)
            clang
            llvmPackages.libclang
            nasm
            openssl
            # misc tooling
            android-tools
            fish
            tshark
            nssTools
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          ANDROID_HOME = "${androidSdk.androidsdk}/libexec/android-sdk";
          ANDROID_SDK_ROOT = "${androidSdk.androidsdk}/libexec/android-sdk";
          ANDROID_NDK_HOME = "${ndk}/libexec/android-sdk/ndk-bundle";
          ANDROID_NDK_ROOT = "${ndk}/libexec/android-sdk/ndk-bundle";
          # AGP otherwise downloads Maven's generic Linux aapt2, which does
          # not run on NixOS. Use the auto-patchelf'd SDK binary instead.
          GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${androidSdk.androidsdk}/libexec/android-sdk/build-tools/35.0.0/aapt2";
        };
      };
    };
}
