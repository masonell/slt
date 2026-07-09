{ inputs, ... }:

{
  perSystem =
    { system, ... }:
    let
      pkgs = import ./pkgs.nix { inherit inputs system; };

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

      cargo-deny = pkgs.rustPlatform.buildRustPackage rec {
        pname = "cargo-deny";
        version = "0.19.9";

        src = pkgs.fetchCrate {
          inherit pname version;
          hash = "sha256-umxJEz4wPgYHWkdBMxCZEs4JDXyKcMt1m3T7U9MFN+Y=";
        };

        cargoLock = {
          lockFileContents = builtins.readFile "${src}/Cargo.lock";
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
        cargo-deny
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
}
