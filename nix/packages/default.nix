{ inputs, ... }:

{
  perSystem =
    { system, ... }:
    let
      pkgs = import ../pkgs.nix { inherit inputs system; };
      lib = pkgs.lib;
      version = (lib.importTOML ../../Cargo.toml).workspace.package.version;
      src = lib.cleanSource ../..;

      linuxTargets = {
        x86_64-linux = {
          musl = "x86_64-linux-musl";
          gnu = "x86_64-linux-gnu";
        };
        aarch64-linux = {
          musl = "aarch64-linux-musl";
          gnu = "aarch64-linux-gnu";
        };
      };

      binaryHashes = {
        musl = {
          x86_64-linux = "sha256-6bsRLF0CnFo5DRZqif0haUV1VyxohzebBSuhKfCzKrY=";
          aarch64-linux = "sha256-2QVr1tgAO5nK1/j+4LuUanxki1IGm2rxpNcAsmzjxY0=";
        };
        gnu = {
          x86_64-linux = "sha256-2DL8575Vd4cYEDMnZr0NyZn7fknjX+yol35ezpZqM/s=";
          aarch64-linux = "sha256-ZiVZD0u0rV665RvBzbl0+y1XbB5SxF6VmXEVVTb9/kk=";
        };
      };

      targetFor =
        kind:
        linuxTargets.${system}.${kind}
          or (throw "SLT does not define a ${kind} release target for ${system}");
    in
    {
      packages = lib.optionalAttrs pkgs.stdenv.isLinux rec {
        slt = pkgs.callPackage ./source.nix {
          inherit src version;
        };

        slt-bin-musl = pkgs.callPackage ./binary.nix {
          inherit version;
          kind = "musl";
          target = targetFor "musl";
          hash = binaryHashes.musl.${system} or lib.fakeHash;
        };

        slt-bin-gnu = pkgs.callPackage ./binary.nix {
          inherit version;
          kind = "gnu";
          target = targetFor "gnu";
          hash = binaryHashes.gnu.${system} or lib.fakeHash;
          autoPatchelf = true;
          runtimeDependencies = [
            pkgs.stdenv.cc.cc.lib
          ];
        };

        default = slt;
      };
    };
}
