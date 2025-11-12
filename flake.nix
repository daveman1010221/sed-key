{
  description = "sed-key: minimal OPAL unlock tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "sed-key";
          version = "0.1.5";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = with pkgs; [
            (rust-bin.stable.latest.default.override {
              targets = [ "x86_64-unknown-linux-musl" ];
            })
            pkg-config
            llvmPackages.libclang
            llvmPackages.llvm
            linuxHeaders
            openssl.dev
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          LLVM_CONFIG_PATH = "${pkgs.llvmPackages.llvm.dev}/bin/llvm-config";
          BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.linuxHeaders}/include";

          OPENSSL_DIR = "${pkgs.openssl}";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";

          meta = with pkgs.lib; {
            description = "Minimal Rust tool to unlock NVMe OPAL SED drives";
            homepage = "https://github.com/daveman1010221/sed-key";
            license = licenses.mit;
            platforms = platforms.linux;
          };
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            (rust-bin.stable.latest.default.override {
              targets = [ "x86_64-unknown-linux-musl" ];
            })
            rust-bindgen
            pkg-config
            llvmPackages.libclang
            llvmPackages.llvm
            linuxHeaders
            openssl
            binutils
            cacert
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          LLVM_CONFIG_PATH = "${pkgs.llvmPackages.llvm.dev}/bin/llvm-config";
          BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.linuxHeaders}/include";

          OPENSSL_DIR = "${pkgs.openssl}";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
          LD_LIBRARY_PATH = "${pkgs.openssl.out}/lib";

          shellHook = ''
            export NIX_HARDENING_ENABLE="fortify stackprotector pie relro bindnow"
            export CARGO_HOME=$PWD/.cargo
            echo "nix-style hardening enabled; cargo builds should match flake outputs."
          '';
        };
      });
}
