#!/bin/sh
# Install the Crucible client, release {version}, connected to {service_url}.
#
#   curl -fsSL {service_url}/install.sh | sh
#   wget -nv -O- {service_url}/install.sh | sh
#
# It does what the README at {service_url}/ sets out step by step:
#   1. checks that this is Linux or macOS, and that you are not root;
#   2. checks that the key this service presents is the one published apart from it,
#      at {published}/service.json, and changes nothing if it is not;
#   3. finds uv 0.8.5 or newer, or installs a private copy for Crucible's use;
#   4. installs release {version} of the client, taking Crucible's own packages from this
#      service only, and Python 3.11 or newer through uv if this machine has none. It
#      tries the new release in a scratch directory first, so an installed client is
#      replaced only by one that installs;
#   5. runs `crucible install {service_url}`: it makes your key and registers it with the
#      service, pins the service's key (the one checked in step 2), adds Crucible's hooks
#      to Claude Code, and starts the sender;
#   6. adds the directory of `crucible` and `crucible-verify` to your PATH, in your
#      shell's start-up files, if it is not there yet.
#
# To run the checks and see the commands without changing anything:
#   curl -fsSL {service_url}/install.sh | CRUCIBLE_INSTALL_DRY_RUN=1 sh
# If you reach PyPI only through a mirror: CRUCIBLE_PYPI_MIRROR=<index URL>.
#
# The whole script is one function, called on its last line, so a download cut short
# runs nothing.

main() {
    set -eu
    unset GREP_OPTIONS  # an older grep reads it; --color=always would wrap what key_id_of reads

    service_url='{service_url}'
    version='{version}'
    published='{published}'
    dry_run="${CRUCIBLE_INSTALL_DRY_RUN:-}"
    mirror="${CRUCIBLE_PYPI_MIRROR:-}"
    private_uv="$HOME/.local/share/crucible/uv"

    say() { printf 'crucible: %s\n' "$*"; }
    die() { printf 'crucible: %s\n' "$*" >&2; exit 1; }
    show() { printf '  would run:'; printf ' %s' "$@"; printf '\n'; }
    run() {
        if [ -n "$dry_run" ]; then show "$@"; else "$@" </dev/null; fi
    }
    fetch() {
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$1"
        elif command -v wget >/dev/null 2>&1; then
            wget -q -O- "$1"
        else
            die "neither curl nor wget is here; install one of them and run this again"
        fi
    }
    at_least() {  # at_least VERSION MINIMUM: is VERSION (x.y.z) at least MINIMUM?
        awk -v a="$1" -v b="$2" 'BEGIN {
            split(a, x, "."); split(b, y, ".")
            for (i = 1; i <= 3; i++) { if (x[i] + 0 > y[i] + 0) exit 0; if (x[i] + 0 < y[i] + 0) exit 1 }
            exit 0 }'
    }
    good_uv() {  # the first uv found that is 0.8.5 or newer
        for candidate in "$(command -v uv 2>/dev/null || true)" "$private_uv/uv" "${XDG_BIN_HOME:-}/uv" \
            "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
            [ -n "$candidate" ] && [ "$candidate" != "/uv" ] && [ -x "$candidate" ] || continue
            have=$("$candidate" --version 2>/dev/null | awk '{print $2}')
            if [ -n "$have" ] && at_least "$have" 0.8.5; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done
        return 1
    }
    key_id_of() {  # the key id a JSON document names: every "key_id" in it well formed and the same, or nothing
        doc=$(cat)
        named=$(printf '%s' "$doc" | grep -o '"key_id"' | wc -l | tr -d ' ')
        ids=$(printf '%s' "$doc" | grep -o '"key_id"[[:space:]]*:[[:space:]]*"sha256:[0-9a-f]\{64\}"' \
            | sed 's/.*"\(sha256:[0-9a-f]\{64\}\)".*/\1/')
        [ "$named" -ge 1 ] && [ "$(printf '%s\n' "$ids" | grep -c .)" = "$named" ] || return 0
        [ "$(printf '%s\n' "$ids" | sort -u | wc -l | tr -d ' ')" = 1 ] || return 0
        printf '%s\n' "$ids" | head -n 1
    }

    [ -n "$dry_run" ] && say "a dry run: checking, and changing nothing"

    # 1. This machine.
    case "$(uname -s)" in
        Linux | Darwin) ;;
        *) die "Crucible runs on Linux and macOS; this is $(uname -s)" ;;
    esac
    [ "$(id -u)" != 0 ] || die "run this as yourself, not as root: Crucible is set up for one user, and needs no sudo"
    [ -n "${HOME:-}" ] || die "HOME is not set"
    had_claude=
    if [ -d "$HOME/.claude" ] || command -v claude >/dev/null 2>&1; then had_claude=1; fi

    # 2. The service's key, against the one published apart from it. Nothing is changed before this.
    served=$(fetch "$service_url/v2/pubkey" | key_id_of) || true
    [ -n "$served" ] || die "cannot read the key $service_url presents; check your connection and run this again"
    listed=$(fetch "$published/service.json" | key_id_of) || true
    [ -n "$listed" ] || die "cannot read the key published at $published/service.json; check your connection and run this again"
    if [ "$served" != "$listed" ]; then
        die "$service_url presents key $served, but $published publishes $listed. Nothing was changed. Do not install from this address."
    fi
    say "the service's key is $served, as published at $published"

    # 3. uv: one already here, if new enough; otherwise a private copy, which touches no start-up file.
    if uv=$(good_uv); then
        :
    else
        say "installing uv for Crucible, from https://astral.sh/uv/, into $private_uv"
        uv="$private_uv/uv"
        if [ -n "$dry_run" ]; then
            show "UV_UNMANAGED_INSTALL=$private_uv" sh "<https://astral.sh/uv/install.sh>"
        else
            installer=$(mktemp)
            fetch https://astral.sh/uv/install.sh >"$installer" || true
            [ -s "$installer" ] || { rm -f "$installer"; die "cannot download uv's installer; check your connection and run this again"; }
            UV_UNMANAGED_INSTALL="$private_uv" sh "$installer" </dev/null >/dev/null || { rm -f "$installer"; die "uv did not install; see https://docs.astral.sh/uv/"; }
            rm -f "$installer"
            [ -x "$uv" ] || die "uv installed, but not at $uv"
        fi
    fi

    # 4. The client, release $version, from this service only.
    uv_install() {  # uv_install [VAR=value ...]: install the client, with that environment
        run env -u UV_CONFIG_FILE -u UV_FIND_LINKS -u UV_OVERRIDE -u UV_EXCLUDE -u UV_INDEX -u UV_INDEX_URL \
            -u UV_EXTRA_INDEX_URL -u UV_DEFAULT_INDEX -u UV_INSECURE_HOST "$@" \
            "$uv" tool install --no-config --reinstall --quiet --python '>=3.11' --index "$service_url/client/simple/" \
            --index-strategy first-index --constraints "$service_url/client/constraints.txt" \
            --with-executables-from crucible-verify "crucible-client==$version"
    }
    say "installing the client, release $version"
    if [ -z "$dry_run" ]; then
        scratch=$(mktemp -d)
        if [ -n "$mirror" ]; then
            uv_install UV_TOOL_DIR="$scratch/tools" UV_TOOL_BIN_DIR="$scratch/bin" UV_DEFAULT_INDEX="$mirror" || ok=no
        else
            uv_install UV_TOOL_DIR="$scratch/tools" UV_TOOL_BIN_DIR="$scratch/bin" || ok=no
        fi
        rm -rf "$scratch"
        [ "${ok:-yes}" = yes ] || die "release $version did not install (see above); any client already installed is unchanged"
    fi
    if [ -n "$dry_run" ]; then
        show env -u UV_CONFIG_FILE "$uv" tool uninstall --no-config crucible-client
    else
        env -u UV_CONFIG_FILE "$uv" tool uninstall --no-config crucible-client </dev/null >/dev/null 2>&1 || true
    fi
    if [ -n "$mirror" ]; then
        uv_install UV_DEFAULT_INDEX="$mirror" || die "release $version did not install (see above); run this again"
    else
        uv_install || die "release $version did not install (see above); run this again"
    fi
    bin=$(env -u UV_CONFIG_FILE "$uv" tool dir --bin --no-config 2>/dev/null) || bin="$HOME/.local/bin"

    # 5. Connect this machine to the service, pinning the key checked in step 2.
    run env -u PYTHONPATH -u PYTHONHOME "$bin/crucible" install "$service_url" --expect-key "$listed" \
        || die "crucible install stopped; see the message above"

    # 6. PATH.
    case ":$PATH:" in
        *":$bin:"*) ;;
        *)
            run env -u UV_CONFIG_FILE "$uv" tool update-shell --no-config || true
            say "open a new terminal to use crucible and crucible-verify by name"
            ;;
    esac

    if [ -n "$dry_run" ]; then
        say "dry run done: nothing was changed"
    elif [ -n "$had_claude" ]; then
        say "done. Start a new Claude Code session: from now on each one is recorded."
        say "to check a session, see \"Check a session\" at $service_url/"
    else
        say "done, but Claude Code was not found. Install it from https://claude.com/claude-code:"
        say "the hooks are in place, and each Claude Code session is recorded from then on."
    fi
}

main "$@"
