{
  description = "Key Server for EmberTalk";

  outputs = { self, nixpkgs }:
  let

    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };

    emberkeyd = pkgs.callPackage ./default.nix {};

  in {
    packages.${system}.default = emberkeyd;

    nixosModules.default = import ./module.nix;
  };
}
