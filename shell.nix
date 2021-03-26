let
  moz_overlay = import (fetchTarball(https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz));
  pkgs = import (fetchTarball("https://github.com/NixOS/nixpkgs/archive/refs/tags/20.09.tar.gz")) {
    overlays = [ moz_overlay ];
  };
  rustnightly = (pkgs.latest.rustChannels.nightly.rust.override {
    extensions = [ "rust-src"];}
  );
in 
  with pkgs;
  stdenv.mkDerivation {
    name = "rust";
    buildInputs = [ 
      rustnightly
      pkgs.openssl 
      pkgs.pkgconfig
      pkgs.rust-analyzer
    ];
}
