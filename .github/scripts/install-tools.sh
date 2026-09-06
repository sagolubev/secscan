#!/usr/bin/env bash
set -euo pipefail
# CI developer tools only. The release executable has none of these dependencies.
tools_dir="${RUNNER_TEMP:?}/secscan-tools"
mkdir -p "$tools_dir"
curl --fail --location --retry 3 \
  https://github.com/Dicklesworthstone/beads_rust/releases/download/v0.2.19/br-0.2.19-linux_amd64.tar.gz \
  --output "$tools_dir/br.tar.gz"
printf '%s  %s\n' 7d30b2976225fa9349d1bf9d972ca9e9046c8e3a39a097f0f7e1474959aa85cf "$tools_dir/br.tar.gz" | sha256sum --check --strict
tar -xzf "$tools_dir/br.tar.gz" -C "$tools_dir" br
chmod +x "$tools_dir/br"
printf '%s\n' "$tools_dir" >> "${GITHUB_PATH:?}"
npm install --global @fission-ai/openspec@1.12.0
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
printf '%s/bin\n' "$(go env GOPATH)" >> "$GITHUB_PATH"
