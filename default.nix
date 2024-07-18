{ rustPlatform
, cmake
, pkg-config
, sqlite
, ... }:

rustPlatform.buildRustPackage {

  pname = "emberkeyd";
  version = "0.1.0";

  src = ./.;

  nativeBuildInputs = [
    cmake
    pkg-config
  ];

  buildInputs = [
    sqlite
  ];

  cargoLock = {
    lockFile = ./Cargo.lock;
  };
}
