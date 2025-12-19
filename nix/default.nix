{
  lib,
  stdenv,
  stdenvAdapters,
  cmake,
  gtest,
  hyprutils,
  hyprwire,
  pam,
  pkg-config,
  sdbus-cpp_2,
  systemdLibs,
  debug ? false,
  doCheck ? debug,
  version ? "git",
  # disable this for older machines without SSE4_2 and AVX2 support
  # whether to use the mold linker
  withMold ? true,
}:
let
  inherit (builtins) foldl';
  inherit (lib.lists) flatten optional;
  inherit (lib.strings) optionalString;

  adapters = flatten [
    (lib.optional withMold stdenvAdapters.useMoldLinker)
    (lib.optional debug stdenvAdapters.keepDebugInfo)
  ];

  customStdenv = foldl' (acc: adapter: adapter acc) stdenv adapters;
in
customStdenv.mkDerivation {
  pname = "hyprauth" + optionalString doCheck "-with-tests" + optionalString debug "-debug";
  inherit version doCheck;

  src = ../.;

  nativeBuildInputs = [
    cmake
    pkg-config
  ];

  buildInputs = flatten [
    (optional doCheck gtest)
    hyprutils
    hyprwire
    pam
    sdbus-cpp_2
    systemdLibs
  ];

  cmakeFlags = [(optionalString doCheck "-DBUILD_TESTING=1")];

  cmakeBuildType =
    if debug
    then "Debug"
    else "RelWithDebInfo";

  meta = {
    homepage = "https://github.com/hyprwm/hyprauth";
    description = "Hyprauth is a parallel authentication library for cli and gui applications";
    license = lib.licenses.bsd3;
    platforms = lib.platforms.linux;
  };
}
