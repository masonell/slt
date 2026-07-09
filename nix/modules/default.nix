{ self, ... }:

let
  sltModule = import ./slt.nix { inherit self; };
in
{
  flake.nixosModules = {
    default = sltModule;
    slt = sltModule;
  };
}
