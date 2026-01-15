{
  description = "A Rust project using Nightly";
  inputs = {
    nixpkgs.url =
      "github:NixOS/nixpkgs/nixos-unstable"; # The overlay allows us to access specific Rust versions (stable/beta/nightly)
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      overlays = [ (import rust-overlay) ];
      pkgs = import nixpkgs { inherit system overlays; };
    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = [
          # Select the latest nightly version
          # You can also specify a date: pkgs.rust-bin.nightly."2024-01-01".default
          pkgs.rust-bin.nightly.latest.default # Add other tools you usually need here
          pkgs.openssl
          pkgs.pkg-config
          pkgs.cargo-generate
          pkgs.bpf-linker
        ];
        # Set environment variables if needed
        RUST_SRC_PATH =
          "${pkgs.rust-bin.nightly.latest.default}/lib/rustlib/src/rust/library";
      };
    };
}
