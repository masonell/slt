{
  description = "SLT — a VPN that multiplexes VPN traffic with standard HTTPS on port 443";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    systems.url = "github:nix-systems/default";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;

      perSystem =
        { system, ... }:
        let
          # Custom nixpkgs import for the unfree Android SDK: its composed build
          # needs allowUnfree and explicit android_sdk.accept_license.
          pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ (import inputs.rust-overlay) ];
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
            platformVersions = [
              "34"
              "35"
            ];
            buildToolsVersions = [
              "34.0.0"
              "35.0.0"
            ];
            includeEmulator = false;
            includeSystemImages = false;
            includeNDK = false;
            includeCmake = false;
            includeSources = false;
          };

          # Auto-patchelf'd NDK (its clang runs on NixOS) for `cargo ndk`.
          ndk = pkgs.androidenv.androidPkgs.ndk-bundle;

          uniffi-bindgen = pkgs.rustPlatform.buildRustPackage rec {
            pname = "uniffi-bindgen";
            version = "0.32.0";

            src = pkgs.fetchCrate {
              pname = "uniffi";
              inherit version;
              hash = "sha256-hWt2z+3qRM3+zyf1qneWioEqNrdTGW2jeTP14fs9YkQ=";
            };

            cargoLock = {
              lockFileContents = builtins.readFile "${src}/Cargo.lock";
            };
            buildFeatures = [ "cli" ];
            cargoBuildFlags = [
              "--bin"
              "uniffi-bindgen"
            ];
            doCheck = false;
          };

          rusty-hook = pkgs.rustPlatform.buildRustPackage rec {
            pname = "rusty-hook";
            version = "0.11.2";

            src = pkgs.fetchCrate {
              inherit pname version;
              hash = "sha256-h+pHLKss/XX0OMWYoEqQEUl7RjI0nN1vGen1HRBuLpw=";
            };

            cargoLock = {
              lockFileContents = builtins.readFile "${src}/Cargo.lock";
              allowBuiltinFetchGit = true;
            };
            doCheck = false;
          };

          rustToolchain = pkgs.rust-bin.stable."1.96.0".default.override {
            extensions = [
              "clippy"
              "rust-analyzer"
              "rust-src"
              "rustfmt"
            ];
            targets = [
              "aarch64-linux-android"
              "x86_64-linux-android"
            ];
          };

          rustPackages = [
            rustToolchain
          ];

          nativeBuildPackages = with pkgs; [
            clang
            cmake
            git
            llvmPackages.libclang
            nasm
            ninja
            openssl
            pkg-config
          ];

          devTools = with pkgs; [
            fish
            nssTools
            tshark
            rusty-hook
          ];

          androidPackages = with pkgs; [
            android-tools
            cargo-ndk
            jdk21
            uniffi-bindgen
          ];

          commonEnv = {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          };

          androidEnv = {
            ANDROID_HOME = "${androidSdk.androidsdk}/libexec/android-sdk";
            ANDROID_SDK_ROOT = "${androidSdk.androidsdk}/libexec/android-sdk";
            ANDROID_NDK_HOME = "${ndk}/libexec/android-sdk/ndk-bundle";
            ANDROID_NDK_ROOT = "${ndk}/libexec/android-sdk/ndk-bundle";
            # AGP otherwise downloads Maven's generic Linux aapt2, which does
            # not run on NixOS. Use the auto-patchelf'd SDK binary instead.
            GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${androidSdk.androidsdk}/libexec/android-sdk/build-tools/35.0.0/aapt2";
          };
        in
        {
          formatter = pkgs.nixfmt-tree;

          devShells.rust = pkgs.mkShell (
            commonEnv
            // {
              packages = rustPackages ++ nativeBuildPackages ++ devTools;
            }
          );

          devShells.default = pkgs.mkShell (
            commonEnv
            // androidEnv
            // {
              packages = rustPackages ++ nativeBuildPackages ++ devTools ++ androidPackages;
            }
          );
        };
    };
}
