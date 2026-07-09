{
  lib,
  rust-bin,
  makeRustPlatform,
  clang,
  cmake,
  git,
  llvmPackages,
  nasm,
  pkg-config,
  src,
  version,
}:

let
  rustToolchain = rust-bin.stable."1.96.0".default;
  rustPlatform = makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };
in
rustPlatform.buildRustPackage {
  pname = "slt";
  inherit src version;

  cargoLock = {
    lockFile = ../../Cargo.lock;
  };

  cargoBuildFlags = [
    "--workspace"
    "--bins"
  ];

  nativeBuildInputs = [
    clang
    cmake
    git
    llvmPackages.libclang
    nasm
    pkg-config
  ];

  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";

  doCheck = false;

  meta = {
    description = "VPN that multiplexes VPN traffic with standard HTTPS on port 443";
    homepage = "https://github.com/masonell/slt";
    license = lib.licenses.asl20;
    mainProgram = "slt";
    platforms = lib.platforms.linux;
  };
}
