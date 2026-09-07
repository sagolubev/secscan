#!/usr/bin/env sh
set -eu

runtime="${CONTAINER_RUNTIME:-docker}"
tag="${SECSCAN_OPENGREP_IMAGE:-secscan-opengrep:1.29.0-rules-6389f1f651ce}"
root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
source_assets="$root/scanner/opengrep/assets"
output_base="${XDG_CACHE_HOME:-$HOME/.cache}/secscan"
assets="$output_base/opengrep/1.29.0"
mkdir -p "$output_base"
mkdir -p "$assets"
output="$(mktemp -d "$output_base/opengrep-image-test.XXXXXX")"
trap 'rm -rf "$output"' EXIT

fetch_asset() {
    name="$1"
    url="$2"
    sha="$3"
    path="$assets/$name"
    if [ -f "$path" ] && echo "$sha  $path" | sha256sum -c - >/dev/null 2>&1; then
        return
    fi
    tmp="$path.tmp"
    curl -fL "$url" -o "$tmp"
    echo "$sha  $tmp" | sha256sum -c -
    chmod 0600 "$tmp"
    mv "$tmp" "$path"
}

fetch_asset opengrep-amd64 \
    https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_musllinux_x86 \
    1b474bf207905a3cffe4e915fe36895835bc89de2620cb2ffd88ca512d9ea31b
fetch_asset opengrep-arm64 \
    https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_musllinux_aarch64 \
    6cccb7466a98608e308204e17b259f4ca3a9028c6eb71e6b07ea21b89026c484
fetch_asset OPENGREP-LICENSE \
    https://raw.githubusercontent.com/opengrep/opengrep/344509d693c852eaac4fc1eeffaf2f655c531b5a/LICENSE \
    20c17d8b8c48a600800dfd14f95d5cb9ff47066a9641ddeab48dc54aec96e331

prepare_rootfs() {
    architecture="$1"
    rootfs="$assets/rootfs-$architecture"
    work="$rootfs.tmp.$$"
    rm -rf "$work"
    mkdir -p "$work/usr/local/bin" "$work/etc" "$work/rules"
    cp "$assets/opengrep-$architecture" "$work/usr/local/bin/opengrep"
    cp "$assets/OPENGREP-LICENSE" "$work/etc/OPENGREP-LGPL-2.1.txt"
    cp "$source_assets/THIRD_PARTY_NOTICES.md" "$work/etc/SECSCAN-THIRD-PARTY-NOTICES.md"
    cp "$source_assets/rules/"* "$work/rules/"
    chmod 0555 "$work/usr/local/bin/opengrep"
    chmod 0444 "$work/etc/"* "$work/rules/"*
    find "$work" -exec touch -t 202608281731.57 {} +
    rm -rf "$rootfs"
    mv "$work" "$rootfs"
}

prepare_rootfs amd64
prepare_rootfs arm64

set -- --pull=false --provenance=false
case "${runtime##*/}" in
    podman) set -- --pull=missing ;;
esac
"$runtime" build "$@" \
    --build-arg SOURCE_DATE_EPOCH=1787938317 \
    --tag "$tag" \
    --file "$source_assets/Dockerfile" \
    "$assets"
"$runtime" run --rm --network none "$tag" --version | grep -F "1.29.0"
test "$("$runtime" image inspect --format '{{.Config.User}}' "$tag")" = "65532:65532"
test "$("$runtime" image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$tag")" = "1.29.0"
test "$("$runtime" image inspect --format '{{index .Config.Labels "io.secscan.rules.digest"}}' "$tag")" = "6389f1f651ceaa52527e17a7ed0675f2c0b2c1933ede4f3e80ac167b886851e8"
"$runtime" run --rm --network none --entrypoint cat "$tag" \
    /etc/OPENGREP-LGPL-2.1.txt | grep -F "GNU LESSER GENERAL PUBLIC LICENSE"

run_scan() {
    language="$1"
    fixture="$2"
    name="$3"
    report="$output/$name.json"
    "$runtime" run --rm \
        --network none \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --tmpfs /tmp:rw,exec,nosuid,nodev,size=256m \
        --mount "type=bind,src=$root/scanner/opengrep/testdata,dst=/target,readonly" \
        "$tag" scan \
        --quiet \
        --disable-version-check \
        --json \
        --config="/rules/$language.yml" \
        "/target/$fixture" >"$report"
}

run_scan python python/vulnerable.py python-vulnerable
run_scan python python/safe.py python-safe
run_scan typescript typescript/vulnerable.ts typescript-vulnerable
run_scan typescript typescript/safe.ts typescript-safe

python3 - "$output" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected = {
    "python-vulnerable": 3,
    "python-safe": 0,
    "typescript-vulnerable": 5,
    "typescript-safe": 0,
}
for name, count in expected.items():
    payload = json.loads((root / f"{name}.json").read_text())
    actual = len(payload.get("results", []))
    if actual != count:
        raise SystemExit(f"{name}: got {actual} findings, want {count}")
PY

"$runtime" image inspect --format '{{.Id}}' "$tag"
