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
          };
        in
        {
          inherit checks;

          devShells.default = pkgs.mkShell {
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
            ];
          };
        }
      );
}
