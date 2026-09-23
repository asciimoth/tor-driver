{
  description = "tor-driver dev env";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-utils = {
      url = "github:numtide/flake-utils";
    };

    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      pre-commit-hooks,
      ...
    }:
    flake-utils.lib.eachSystem
      [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };

          goModCheck =
            command:
            pkgs.writeShellScript "go-module-check" ''
              if test -f go.mod; then
                exec ${command}
              fi
            '';

          checks = {
            pre-commit-check = pre-commit-hooks.lib.${system}.run {
              src = ./.;
              hooks = {
                commitizen.enable = true;
                typos.enable = true;
                typos-commit = {
                  enable = true;
                  description = "Find typos in commit messages";
                  entry = builtins.toString (
                    pkgs.writeShellScript "typos-commit" ''
                      typos "$1"
                    ''
                  );
                  stages = [ "commit-msg" ];
                };

                gofmt.enable = true;
                govet.enable = true;
                golangci-lint.enable = true;
                gotidy = {
                  enable = true;
                  description = "Check that go.mod matches the source code";
                  entry = builtins.toString (goModCheck "${pkgs.go}/bin/go mod tidy -diff");
                  pass_filenames = false;
                };
                golangtest = {
                  enable = true;
                  description = "Run Go tests with the race detector";
                  entry = builtins.toString (goModCheck "${pkgs.go}/bin/go test -race -timeout 2m ./...");
                  pass_filenames = false;
                };
              };
            };
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            winvm-host = pkgs.runCommand "tor-driver-winvm-host-tests" {
              nativeBuildInputs = with pkgs; [
                bash
                coreutils
                findutils
                git
                gnugrep
                gnutar
                jq
                python3
                qemu
                OVMF
                util-linux
              ];
            } ''
              cp -R ${./.} source
              chmod -R u+w source
              cd source
              patchShebangs dev/winvm
              export WINVM_OVMF_CODE=${pkgs.OVMF.fd}/FV/OVMF_CODE.fd
              export WINVM_OVMF_VARS=${pkgs.OVMF.fd}/FV/OVMF_VARS.fd
              bash dev/winvm/tests/host-scripts.sh
              touch $out
            '';
          };
        in
        {
          inherit checks;

          devShells.default = pkgs.mkShell ({
            inherit (checks.pre-commit-check) shellHook;

            TOR_BINARY = "${pkgs.tor}/bin/tor";
            TOR_OBFS4_BINARY = "${pkgs.obfs4}/bin/lyrebird";

            packages = with pkgs; [
              go
              golangci-lint
              gopls

              typos
              commitizen
              just

              tor
              obfs4
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux (with pkgs; [
              qemu
              OVMF
              xorriso
              openssh
              jq
              python3
              curl
              util-linux
            ]);
          } // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            WINVM_OVMF_CODE = "${pkgs.OVMF.fd}/FV/OVMF_CODE.fd";
            WINVM_OVMF_VARS = "${pkgs.OVMF.fd}/FV/OVMF_VARS.fd";
          });
        }
      );
}
