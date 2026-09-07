#!/usr/bin/env bash
set -euo pipefail

# This provisions only an ephemeral GitHub runner. Local tests use an existing
# configured daemon; secscan itself never provisions users or container engines.
test "${GITHUB_ACTIONS:-}" = true
: "${RUNNER_TEMP:?}" "${GITHUB_ENV:?}"
mode=${1:?namespace mode}
case "$mode" in docker-userns|docker-rootless|podman-rootless) ;; *) exit 2 ;; esac

uid=$(id -u)
user=$(id -un)
runtime_dir=/run/user/$uid
printf '{}\n' > "$RUNNER_TEMP/secscan-daemon.json"

case "$mode" in
  docker-userns)
    export SECSCAN_RUNTIME=docker
    export DOCKER_HOST=unix:///run/secscan-userns.sock
    features=()
    major=$(dockerd --version | sed -E 's/^Docker version ([0-9]+).*/\1/')
    if (( major >= 29 )); then features=(--feature containerd-snapshotter=false); fi
    sudo systemd-run --unit=secscan-userns --property=Delegate=yes \
      dockerd --config-file "$RUNNER_TEMP/secscan-daemon.json" \
      --data-root "$RUNNER_TEMP/docker-userns" --exec-root /run/secscan-userns \
      --host "$DOCKER_HOST" --pidfile /run/secscan-userns.pid \
      --group "$(id -gn)" --userns-remap=default \
      --bridge=none --iptables=false --ip-forward=false --ip-masq=false "${features[@]}"
    ;;
  docker-rootless)
    # Match the daemon package; mixing rootless helpers and dockerd versions
    # changes startup behavior and does not test a supported installation.
    package_version=$(dpkg-query -W -f='${Version}' docker-ce)
    sudo apt-get update
    sudo apt-get install -y uidmap slirp4netns dbus-user-session \
      "docker-ce-rootless-extras=$package_version"
    sudo loginctl enable-linger "$user"
    sudo systemctl start "user@$uid.service"
    export XDG_RUNTIME_DIR=$runtime_dir
    export DBUS_SESSION_BUS_ADDRESS=unix:path=$runtime_dir/bus
    export SECSCAN_RUNTIME=docker
    export DOCKER_HOST=unix://$runtime_dir/secscan-docker.sock
    systemd-run --user --unit=secscan-rootless --property=Delegate=yes \
      --setenv="PATH=$PATH" --setenv="XDG_RUNTIME_DIR=$runtime_dir" \
      --setenv="DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR=$RUNNER_TEMP/rootlesskit" \
      dockerd-rootless.sh --rootless --config-file "$RUNNER_TEMP/secscan-daemon.json" \
      --data-root "$RUNNER_TEMP/docker-rootless" --exec-root "$runtime_dir/secscan-docker" \
      --host "$DOCKER_HOST" --pidfile "$runtime_dir/secscan-docker.pid"
    printf 'XDG_RUNTIME_DIR=%s\n' "$XDG_RUNTIME_DIR" >> "$GITHUB_ENV"
    ;;
  podman-rootless)
    sudo apt-get update
    sudo apt-get install -y podman uidmap slirp4netns fuse-overlayfs
    export SECSCAN_RUNTIME=podman
    export CONTAINERS_CONF=$RUNNER_TEMP/secscan-containers.conf
    printf '[engine]\ncgroup_manager="cgroupfs"\n' > "$CONTAINERS_CONF"
    printf 'CONTAINERS_CONF=%s\n' "$CONTAINERS_CONF" >> "$GITHUB_ENV"
    ;;
esac

ready=false
for attempt in {1..60}; do
  if "$SECSCAN_RUNTIME" info > /dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  "$SECSCAN_RUNTIME" info
  exit 1
fi
printf 'SECSCAN_RUNTIME=%s\nSECSCAN_EXPECTED_NAMESPACE=%s\n' "$SECSCAN_RUNTIME" "$mode" >> "$GITHUB_ENV"
if [[ "$SECSCAN_RUNTIME" == docker ]]; then printf 'DOCKER_HOST=%s\n' "$DOCKER_HOST" >> "$GITHUB_ENV"; fi
"$SECSCAN_RUNTIME" pull ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
