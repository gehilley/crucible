#!/bin/sh
# Install the Crucible client, release {version}, connected to {service_url}.
#
#   curl -fsSL {service_url}/install.sh | sh
#   wget -qO- {service_url}/install.sh | sh
#
# It does what the README at {service_url}/ sets out step by step:
#   1. checks that this is Linux or macOS, and that you are not root;
#   2. finds uv 0.8.5 or newer, installing or updating it if it must;
#   3. checks that the key this service presents is the one published apart from it,
#      at {published}/service.json, and installs nothing if it is not;
#   4. installs release {version} of the client, taking Crucible's own packages from this
#      service only;
#   5. runs `crucible install {service_url}`: it makes your key, pins the service's
#      key, adds Crucible's hooks to Claude Code, and starts the sender.
#
# To run the checks and see the commands without changing anything:
#   curl -fsSL {service_url}/install.sh | CRUCIBLE_INSTALL_DRY_RUN=1 sh
#
# The whole script is one function, called on its last line, so a download cut short
# runs nothing.

main() {
    set -eu

    service_url='{service_url}'
    version='{version}'
    published='{published}'
    dry_run="${CRUCIBLE_INSTALL_DRY_RUN:-}"

    say() { printf 'crucible: %s\n' "$*"; }
    die() { printf 'crucible: %s\n' "$*" >&2; exit 1; }
    run() {
        if [ -n "$dry_run" ]; then
            printf '  would run:'
            printf ' %s' "$@"
            printf '\n'
        else
            "$@" </dev/null
        fi
    }
    fetch() {
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$1"
        elif command -v wget >/dev/null 2>&1; then
            wget -qO- "$1"
        else
            die "neither curl nor wget is here; install one of them and run this again"
        fi
    }
    at_least() {  # at_least VERSION MINIMUM: is VERSION (x.y.z) at least MINIMUM?
        awk -v a="$1" -v b="$2" 'BEGIN {
            n = split(a, x, "."); split(b, y, ".")
            for (i = 1; i <= 3; i++) { if (x[i] + 0 > y[i] + 0) exit 0; if (x[i] + 0 < y[i] + 0) exit 1 }
            exit 0 }'
    }
    find_uv() {
        if command -v uv >/dev/null 2>&1; then command -v uv; return 0; fi
        for d in "${XDG_BIN_HOME:-}" "$HOME/.local/bin" "$HOME/.cargo/bin"; do
            if [ -n "$d" ] && [ -x "$d/uv" ]; then printf '%s\n' "$d/uv"; return 0; fi
        done
        return 1
    }
    key_id_of() {
        sed -n 's/.*"key_id"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' | head -n 1
    }

    [ -n "$dry_run" ] && say "a dry run: checking, and changing nothing"

    # 1. This machine.
    case "$(uname -s)" in
        Linux | Darwin) ;;
        *) die "Crucible runs on Linux and macOS; this is $(uname -s)" ;;
    esac
    [ "$(id -u)" != 0 ] || die "run this as yourself, not as root: Crucible is set up for one user, and needs no sudo"
    [ -n "${HOME:-}" ] || die "HOME is not set"

    # 2. uv.
    if uv=$(find_uv); then
        have=$("$uv" --version 2>/dev/null | awk '{print $2}')
        if ! at_least "${have:-0}" 0.8.5; then
            say "uv $have is older than 0.8.5; updating it"
            run "$uv" self update || die "uv $have could not update itself; update it (https://docs.astral.sh/uv/) and run this again"
        fi
    else
        say "uv is not here; installing it from https://astral.sh/uv/ (into ~/.local/bin)"
        if [ -n "$dry_run" ]; then
            uv="$HOME/.local/bin/uv"
            printf '  would run: fetch https://astral.sh/uv/install.sh | sh\n'
        else
            fetch https://astral.sh/uv/install.sh | sh >/dev/null || die "uv did not install; see https://docs.astral.sh/uv/"
            uv=$(find_uv) || die "uv installed, but cannot be found; open a new terminal and run this again"
        fi
    fi

    # 3. The service's key, against the one published apart from it.
    served=$(fetch "$service_url/v2/pubkey" | key_id_of) || true
    [ -n "$served" ] || die "cannot read the key $service_url presents; check your connection and run this again"
    listed=$(fetch "$published/service.json" | key_id_of) || true
    [ -n "$listed" ] || die "cannot read the key published at $published/service.json; check your connection and run this again"
    if [ "$served" != "$listed" ]; then
        die "$service_url presents key $served, but $published publishes $listed. Nothing was installed. Do not install from this address."
    fi
    say "the service's key is $served, as published at $published"

    # 4. The client, release $version, from this service only.
    say "installing the client, release $version"
    if [ -z "$dry_run" ]; then
        env -u UV_CONFIG_FILE "$uv" tool uninstall --no-config crucible-client </dev/null >/dev/null 2>&1 || true
    fi
    run env -u UV_CONFIG_FILE -u UV_FIND_LINKS -u UV_OVERRIDE -u UV_EXCLUDE -u UV_INDEX -u UV_INDEX_URL \
        -u UV_EXTRA_INDEX_URL -u UV_DEFAULT_INDEX -u UV_INSECURE_HOST \
        "$uv" tool install --no-config --reinstall --quiet --index "$service_url/client/simple/" \
        --index-strategy first-index --constraints "$service_url/client/constraints.txt" \
        --with-executables-from crucible-verify "crucible-client==$version" \
        || die "the client did not install; see the message above"
    bin=$(env -u UV_CONFIG_FILE "$uv" tool dir --bin --no-config 2>/dev/null) || bin="$HOME/.local/bin"

    # 5. Connect this machine to the service.
    run env -u PYTHONPATH -u PYTHONHOME "$bin/crucible" install "$service_url" || die "crucible install stopped; see the message above"

    case ":$PATH:" in
        *":$bin:"*) ;;
        *)
            run env -u UV_CONFIG_FILE "$uv" tool update-shell --no-config >/dev/null 2>&1 || true
            say "open a new terminal to use crucible and crucible-verify by name"
            ;;
    esac
    if [ ! -d "$HOME/.claude" ] && ! command -v claude >/dev/null 2>&1; then
        say "Claude Code was not found. Crucible records Claude Code sessions: install it from https://claude.com/claude-code"
    fi

    if [ -n "$dry_run" ]; then
        say "dry run done: nothing was changed"
    else
        say "done. Start a new Claude Code session: from now on each one is recorded."
        say "to check a session, see \"Check a session\" at $service_url/"
    fi
}

main "$@"
