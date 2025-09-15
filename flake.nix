{
  description = "sed-key: minimal OPAL unlock tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; # or your preferred channel
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage rec {
          pname = "sed-key";
          version = "0.1.0";

          src = ./.; # local source

          cargoLock.lockFile = ./Cargo.lock;

          # If you want to ensure libclang is available at build time:
          nativeBuildInputs = with pkgs; [ pkg-config llvmPackages.libclang ];

          # Optional meta info:
          meta = with pkgs.lib; {
            description = "Minimal Rust tool to unlock NVMe OPAL SED drives";
            homepage = "https://github.com/yourname/sed-key";
            license = licenses.mit;
            maintainers = [ maintainers.yourname ];
            platforms = platforms.linux;
          };
        };
      });
}

