{
  description = "nixos-tor-anti-dos: per-source rate limiting for a Tor relay's ORPort";

  # A stable channel, because nothing here needs a recent nixpkgs: the module
  # uses networking.nftables.tables and nothing newer. The lock file, not the
  # channel name, is what makes this reproducible.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      nixosModules.default = ./nixos/tor-anti-dos.nix;
      nixosModules.tor-anti-dos = ./nixos/tor-anti-dos.nix;

      checks.${system} = {
        antidos = import ./tests/antidos.nix { inherit pkgs; module = self.nixosModules.default; };
      };
    };
}
