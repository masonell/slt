{
  lib,
  stdenvNoCC,
  fetchzip,
  autoPatchelfHook,
  target,
  version,
  hash,
  kind,
  autoPatchelf ? false,
  releaseBaseUrl ? "https://github.com/masonell/slt/releases/download/${version}",
  archiveName ? "slt-${version}-${target}.tar.gz",
  runtimeDependencies ? [ ],
}:

stdenvNoCC.mkDerivation {
  pname = "slt-bin-${kind}";
  inherit version;

  src = fetchzip {
    url = "${releaseBaseUrl}/${archiveName}";
    inherit hash;
  };

  nativeBuildInputs = lib.optionals autoPatchelf [
    autoPatchelfHook
  ];

  buildInputs = runtimeDependencies;

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p "$out/bin"
    for bin in slt slt-client slt-server; do
      candidate="$(find . -type f -name "$bin" | head -n 1)"
      if [ -z "$candidate" ]; then
        echo "missing $bin in ${archiveName}" >&2
        exit 1
      fi
      install -Dm755 "$candidate" "$out/bin/$bin"
    done

    runHook postInstall
  '';

  meta = {
    description = "Prebuilt SLT VPN binaries for ${target}";
    homepage = "https://github.com/masonell/slt";
    license = lib.licenses.asl20;
    mainProgram = "slt";
    platforms = lib.platforms.linux;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}
