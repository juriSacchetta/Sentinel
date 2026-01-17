{
  description = "Aya eBPF Dev Shell (The Pragmatic Way)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      overlays = [ (import rust-overlay) ];
      pkgs = import nixpkgs { inherit system overlays; };

      rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
        extensions = [ "rust-src" "rust-analyzer" ];
      };

    in {
      devShells.${system}.default = pkgs.mkShell {
        # 1. System Dependencies
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [
          pkgs.openssl
          pkgs.rust-bindgen # System-wide bindgen
          pkgs.bpf-linker
          pkgs.bpftools
          pkgs.llvmPackages.bintools
          pkgs.elfutils # Often needed for eBPF
          pkgs.zlib
          rustToolchain

          (pkgs.writeScriptBin "rustup" ''
            #!${pkgs.runtimeShell}
            # Catch the 'rustup run nightly cargo ...' command 
            # and just run 'cargo ...' instead.
            if [ "$1" = "run" ]; then shift 2; fi
            exec "$@"
          '')
        ];

        # 2. Environment Variables
        RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

        # 3. The "Just Work" Hook
        shellHook = ''
          # Add standard Cargo bin to PATH so installed tools work
          export PATH="$HOME/.cargo/bin:$PATH"

          echo "🦀 eBPF Environment Ready"
          echo "To install aya-tool, run this once:"
          echo "  cargo install --git https://github.com/aya-rs/aya -- aya-tool"
        '';
      };
    };
}
