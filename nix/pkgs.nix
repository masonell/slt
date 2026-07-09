{ inputs, system }:

import inputs.nixpkgs {
  inherit system;
  overlays = [ (import inputs.rust-overlay) ];
  config = {
    allowUnfree = true;
    android_sdk.accept_license = true;
  };
}
