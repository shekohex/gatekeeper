{
  description = "Gatekeeper development environment";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        lib = pkgs.lib;
      in
      {
        devShells.default = pkgs.mkShell {
          name = "gatekeeper";
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.clang
            pkgs.cmake
            pkgs.ninja
            pkgs.dfu-util
            pkgs.ldproxy
            pkgs.libiconv
          ];
          venvDir = "./.venv";
          buildInputs = [
            pkgs.python3Packages.venvShellHook
            # We want the unwrapped version, wrapped comes with nixpkgs' toolchain
            pkgs.rust-analyzer-unwrapped

            pkgs.rustup
            pkgs.cargo
            pkgs.rustfmt
            pkgs.clippy
            pkgs.cargo-nextest
            pkgs.cargo-generate
            pkgs.just
            pkgs.openocd
            pkgs.espup
            pkgs.espflash
            pkgs.python3
          ];
          packages = [ ];
          # Environment variables
          # RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
          CRATE_CC_NO_DEFAULTS = "1";
          shellHook = ''
            source ./export-esp.sh
          '';
        };
      });
}
