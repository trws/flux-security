{
  description = "flux-security";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-22.11";
    flake-utils.url = "github:numtide/flake-utils";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };
  outputs = { self, nixpkgs, flake-utils, ... }:
  flake-utils.lib.eachSystem [
    "aarch64-linux"
    "powerpc64le-linux"
    "x86_64-linux"
  ]
  (system:
  let
    pkgs = nixpkgs.legacyPackages.${system};
          # get something close to the `git describe` based version that works
          # inside a flake build
          version_base = builtins.head (builtins.match "^flux-security version ([^ ]*) .*" (builtins.readFile "${self}/NEWS.md"));
          version_rev = if self ? "shortRev" then "${self.shortRev}" else "dirty";
          version_revcount = if self ? "revCount" then (toString self.revCount) else "dirty";
          version_suffix = if version_revcount == "0" then "" else "-${version_revcount}-${version_rev}";

          basePython = pkgs.python310;
  in
  rec {
    devShells.default = self.packages.${system}.default.overrideAttrs (
      final: prev: {
              # avoid patching scripts in the working copy
              preBuild = ''
                # zsh can cause problems with buildPhase, use something fast
                export SHELL=dash
              '';
            }
            );
          # Special extended development shell with linters and other goodies
          devShells.dev = self.devShells.${system}.default.overrideAttrs (
            final: prev: {
              nativeBuildInputs = prev.nativeBuildInputs ++ (with pkgs; [
                bear
                clang-tools
              ]) ++ (with basePython.pkgs; [
                black
              ]
              );
            }
            );
            packages.default = pkgs.stdenv.mkDerivation {
              pname = "flux-security";
              version = "${version_base}${version_suffix}";
              buildInputs = with pkgs ; [
              # hooks
              autoreconfHook

              libxcrypt # for libcrypt
              libsodium
              (munge.overrideAttrs (prev: {
                # fix broken nixpkgs munge package to install pkgconfig files
                preAutoreconf = "";
                configureFlags = prev.configureFlags ++ [
                  "--with-pkgconfigdir=${placeholder "out"}/lib/pkgconfig"
                  "localstatedir=${placeholder "out"}/var"
                ];
              }))
              jansson
              libuuid
              pam
              libpam-wrapper # for tests
              basePython
            ] ++ (with basePython.pkgs; [
              sphinx
            ]);
            nativeBuildInputs = with pkgs; [
              bash
              dash

              # build system
              pkg-config
              autoconf
              automake
              libtool
              m4
            ];

            enableParallelBuilding = true;
            src = self;
            hardeningDisable = [ "bindnow" ];
            configureFlags = [
              "--enable-pam"
            ];
            autoreconfPhase = ''
              export FLUX_VERSION=$version
              ./autogen.sh
            '';
            preBuild = ''
              # zsh can cause problems with buildPhase, use something fast
              export SHELL=dash
              patchShebangs src
              patchShebangs doc
              patchShebangs etc
            '';
          };
        }
        );
      }
