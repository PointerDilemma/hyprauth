{
  self,
  lib,
  inputs,
}: let
  mkDate = longDate: (lib.concatStringsSep "-" [
    (builtins.substring 0 4 longDate)
    (builtins.substring 4 2 longDate)
    (builtins.substring 6 2 longDate)
  ]);

  version = lib.removeSuffix "\n" (builtins.readFile ../VERSION);
in {
  default = inputs.self.overlays.hyprauth;

  hyprauth = lib.composeManyExtensions [
    inputs.hyprutils.overlays.default
    inputs.hyprwire.overlays.default
    (final: prev: {
      hyprauth = prev.callPackage ./default.nix {
        stdenv = prev.gcc15Stdenv;
        version =
          version
          + "+date="
          + (mkDate (inputs.self.lastModifiedDate or "19700101"))
          + "_"
          + (inputs.self.shortRev or "dirty");
      };
      hyprauth-with-tests = final.hyprauth.override {doCheck = true;};
    })
  ];

  # Debug
  hyprauth-debug = lib.composeManyExtensions [
    # Dependencies
    self.overlays.hyprauth

    (final: prev: {
      hyprutils = prev.hyprutils.override {debug = true;};
      # TODO: add debug = true to hyprwire
      hyprwire = prev.hyprwire.overrideAttrs {
        cmakeBuildType = "Debug";
        dontStrip = true;
      };
      hyprauth-debug = prev.hyprauth.override {debug = true;};
    })
  ];
}
