{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default-linux";

    hyprutils = {
      url = "github:hyprwm/hyprutils";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        systems.follows = "systems";
      };
    };

    hyprwire = {
      #url = "git+file:///home/max/desk/hyprwire";
      url = "github:hyprwm/hyprwire";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        systems.follows = "systems";
        hyprutils.follows = "hyprutils";
      };
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      systems,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      eachSystem = lib.genAttrs (import systems);
      pkgsFor = eachSystem (
        system:
        import nixpkgs {
          localSystem.system = system;
          overlays = with self.overlays; [hyprauth];
        }
      );
      pkgsDebugFor = eachSystem (system:
        import nixpkgs {
          localSystem = system;
          overlays = with self.overlays; [hyprauth-debug];
        });
    in
    {
      overlays = import ./nix/overlays.nix { inherit self lib inputs; };

      packages = eachSystem (system: {
        default = self.packages.${system}.hyprauth;
        inherit (pkgsFor.${system}) hyprauth hyprauth-with-tests;
        inherit (pkgsDebugFor.${system}) hyprauth-debug;
      });

      checks = eachSystem (system: self.packages.${system});

      formatter = eachSystem (system: pkgsFor.${system}.alejandra);
    };
}
