{
  description = "sed-key: minimal OPAL unlock tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "sed-key";
          version = "0.1.2";

          src = ./.; # local source

          cargoLock.lockFile = ./Cargo.lock;

          # bring libclang + llvm-config into the sandbox
          nativeBuildInputs = with pkgs; [
            pkg-config
            llvmPackages.libclang
            llvmPackages.llvm
            linuxHeaders
          ];

          # explicitly tell clang-sys where to find stuff
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          LLVM_CONFIG_PATH = "${pkgs.llvmPackages.llvm.dev}/bin/llvm-config";

          # Add kernel header path to bindgen
          BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.linuxHeaders}/include";

          meta = with pkgs.lib; {
            description = "Minimal Rust tool to unlock NVMe OPAL SED drives";
            homepage = "https://github.com/daveman1010221/sed-key";
            license = licenses.mit;
            platforms = platforms.linux;
          };
        };

        # Dev shell for hacking
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            pkg-config
            llvmPackages.libclang
            llvmPackages.llvm
            linuxHeaders
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          LLVM_CONFIG_PATH = "${pkgs.llvmPackages.llvm.dev}/bin/llvm-config";
          BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.linuxHeaders}/include";
        };
      });
}
