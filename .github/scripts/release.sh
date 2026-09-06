#!/usr/bin/env bash
set -euo pipefail
tag=${GITHUB_REF_NAME:?}
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'Release tag must be vMAJOR.MINOR.PATCH\n' >&2
  exit 2
fi
files=(dist/secscan-linux-amd64 dist/secscan-linux-arm64 dist/secscan-darwin-amd64 dist/secscan-darwin-arm64)
for file in "${files[@]}"; do test -s "$file"; done
if [[ $(find dist -type f | wc -l) -ne 4 ]]; then
  printf 'Unexpected release artifact set\n' >&2
  exit 1
fi
chmod +x dist/secscan-linux-amd64
test "$(dist/secscan-linux-amd64 --version)" = "secscan $tag"
dist/secscan-linux-amd64 --licenses > "${RUNNER_TEMP:?}/release-licenses.txt"
grep -q 'MIT License' "$RUNNER_TEMP/release-licenses.txt"
(cd dist && sha256sum secscan-* > SHA256SUMS && sha256sum --check SHA256SUMS)
cat > "$RUNNER_TEMP/release-notes.md" <<'NOTES'
Standalone secscan executables for Linux and macOS, amd64 and arm64.

Download the executable for your system, verify SHA256SUMS, and make it executable with chmod +x. Run --version and --licenses to inspect the build and its notices.

Git and Docker or Podman are required for scanning. Run secscan update before the first scan. Scanner engines and databases are separate downloads and are not included in these assets. See README for coverage and runtime limitations.
NOTES
gh release create "$tag" --draft --verify-tag --title "secscan $tag" --notes-file "$RUNNER_TEMP/release-notes.md"
gh release upload "$tag" "${files[@]}" dist/SHA256SUMS
gh release edit "$tag" --draft=false --latest
