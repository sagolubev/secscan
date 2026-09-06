#!/bin/sh
# Install a verified release executable without a compiler or elevated privileges.
set -eu
umask 077

repository=https://github.com/sagolubev/secscan
work_dir=
staged_file=

fail() {
    printf 'secscan installer: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [ -n "$staged_file" ]; then rm -f "$staged_file"; fi
    if [ -n "$work_dir" ]; then rm -rf "$work_dir"; fi
}

usage() {
    printf '%s\n' \
        'Usage: sh install.sh [--version vMAJOR.MINOR.PATCH] [--dir DIRECTORY]' \
        'Defaults: latest stable release, ~/.local/bin' \
        'Requires curl and sha256sum or shasum. Does not install scanner engines.'
}

download() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --fail --silent --show-error --location --retry 3 \
        --connect-timeout 15 --max-time 180 "$@"
}

valid_version() {
    case "$version" in
        ''|*[!v0-9.]*) return 1 ;;
    esac
    printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

check_destination() {
    if [ -L "$target" ] || [ -d "$target" ]; then
        fail "destination is a symlink or directory: $target"
    fi
    if [ -e "$target" ] && [ ! -f "$target" ]; then
        fail "destination is not a regular file: $target"
    fi
}

main() {
    version=latest
    install_dir=${HOME:?HOME must be set}/.local/bin
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version)
                [ "$#" -ge 2 ] || fail '--version requires a value'
                version=$2
                shift 2
                ;;
            --dir)
                [ "$#" -ge 2 ] && [ -n "$2" ] || fail '--dir requires a directory'
                install_dir=$2
                shift 2
                ;;
            --help|-h) usage; return ;;
            *) fail "unknown argument: $1" ;;
        esac
    done
    if [ "$version" != latest ]; then
        valid_version ||
            fail 'version must be vMAJOR.MINOR.PATCH'
    fi
    case "$(uname -s)" in
        Linux) platform=linux ;;
        Darwin) platform=darwin ;;
        *) fail 'supported systems are Linux and macOS' ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) architecture=amd64 ;;
        arm64|aarch64) architecture=arm64 ;;
        *) fail 'supported architectures are amd64 and arm64' ;;
    esac
    command -v curl >/dev/null 2>&1 || fail 'curl is required'
    if command -v sha256sum >/dev/null 2>&1; then
        checksum_tool=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        checksum_tool=shasum
    else
        fail 'sha256sum or shasum is required'
    fi
    case "$install_dir" in
        /*) ;;
        *) install_dir=$PWD/$install_dir ;;
    esac
    target=$install_dir/secscan
    check_destination
    if [ "$version" = latest ]; then
        release_url=$(download --output /dev/null --write-out '%{url_effective}' "$repository/releases/latest") ||
            fail 'could not resolve the latest release'
        case "$release_url" in
            "$repository/releases/tag/"*) version=${release_url#"$repository/releases/tag/"} ;;
            *) fail 'unexpected latest release URL' ;;
        esac
        valid_version ||
            fail 'latest release is not a stable version tag'
    fi
    work_dir=$(mktemp -d "${TMPDIR:-/tmp}/secscan-install.XXXXXXXX") ||
        fail 'could not create temporary download directory'
    asset=secscan-$platform-$architecture
    release=$repository/releases/download/$version
    download --output "$work_dir/$asset" "$release/$asset" ||
        fail 'binary download failed'
    download --output "$work_dir/SHA256SUMS" "$release/SHA256SUMS" ||
        fail 'checksum download failed'
    expected=$(awk -v asset="$asset" '$2 == asset { value=$1; count++; if (NF != 2) invalid=1 } END { if (count != 1 || invalid) exit 1; print value }' "$work_dir/SHA256SUMS") ||
        fail 'expected exactly one checksum for the selected binary'
    printf '%s\n' "$expected" | LC_ALL=C grep -Eq '^[0-9a-f]{64}$' ||
        fail 'invalid release checksum'
    if [ "$checksum_tool" = sha256sum ]; then
        actual=$(sha256sum < "$work_dir/$asset") || fail 'SHA256 calculation failed'
    else
        actual=$(shasum -a 256 < "$work_dir/$asset") || fail 'SHA256 calculation failed'
    fi
    actual=${actual%% *}
    [ "$actual" = "$expected" ] || fail 'SHA256 mismatch; nothing installed'

    mkdir -p "$install_dir" || fail 'cannot create installation directory'
    staged_file=$(mktemp "$install_dir/.secscan.XXXXXXXX") ||
        fail 'installation directory is not writable'
    cp "$work_dir/$asset" "$staged_file" || fail 'could not stage the binary'
    chmod 755 "$staged_file" || fail 'could not make the binary executable'
    installed_version=$("$staged_file" --version </dev/null) ||
        fail 'verified binary could not run on this system'
    [ "$installed_version" = "secscan $version" ] ||
        fail 'binary version does not match the release'
    check_destination
    mv -f "$staged_file" "$target" || fail 'could not replace the installed binary'
    staged_file=
    printf 'Installed secscan %s at %s\n' "$version" "$target"
    case ":${PATH-}:" in
        *":$install_dir:"*) ;;
        *) printf '%s\n' 'Add the installation directory to PATH, or run the binary by its full path.' ;;
    esac
}

trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
main "$@"
