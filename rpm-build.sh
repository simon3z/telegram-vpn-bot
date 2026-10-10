#!/usr/bin/env bash
#
# rpm-build.sh - build the telegram-vpn-bot Fedora RPM from the current branch.
#
# Usage:
#   ./rpm-build.sh        # generate sources, build the RPMs, show result
#   ./rpm-build.sh lint    # rpmlint the built SRPM and RPMs
#
# Conventions (shared with the steelbx repo):
#   * version = latest git tag (override with TELEGRAM_VPN_BOT_VERSION;
#     falls back to the Cargo.toml version when the repo has no tags)
#   * release = commits since the last tag + 1 (1 when there are no tags)
#   * the spec's Version: and License: must be up to date; verified here
#   * topdir = ./rpmbuild (local to this checkout)
#
# Requires: cargo, python3, rpmbuild, xz, git, and cargo-rpm-macros
#          (macros + cargo_vendor fileattr hook for the bundled
#          crate provides); rpmlint only for lint mode.

set -euo pipefail
cd "$(dirname "$0")"

NAME=telegram-vpn-bot
SPEC=telegram-vpn-bot.spec

# Version: env override, else latest git tag (v-prefix stripped), else
# the Cargo.toml version (this repo currently has no tags).
if [ -n "${TELEGRAM_VPN_BOT_VERSION:-}" ]; then
    VERSION="$TELEGRAM_VPN_BOT_VERSION"
elif last_tag=$(git describe --tags --abbrev=0 2>/dev/null); then
    VERSION="${last_tag#v}"
else
    VERSION="$(python3 -c \
        'import tomllib; print(tomllib.load(open("Cargo.toml","rb"))["package"]["version"])')"
fi

RPM_TOP="$(pwd)/rpmbuild"
mkdir -p "${RPM_TOP}"/{SOURCES,SPECS,BUILD,BUILDROOT,SRPMS,RPMS,TMP}

# Release number: commits since the last tag + 1 (1 if no tags).
release_number() {
    if last_tag=$(git describe --tags --abbrev=0 2>/dev/null); then
        echo $(( $(git rev-list --count "${last_tag}..HEAD") + 1 ))
    else
        echo 1
    fi
}

# Language-specific below; the shared part is kept in sync with steelbx.

# Print the cumulative SPDX expression the spec's License: must declare
# (project + all vendored crates): every atomic license of each Cargo.toml
# `license` field (OR/AND flattened), deduplicated, project license first,
# rest sorted, joined with AND. Runs with vendor/ present.
license_expression() {
    python3 - <<'PY'
import re, tomllib
from pathlib import Path

def atoms(l):
    l = l.replace("(", " ").replace(")", " ")
    return [t.strip() for t in re.split(r"\s+(?:OR|AND)\s+", l) if t.strip()]

lics = [tomllib.loads(Path("Cargo.toml").read_text())["package"]["license"]]
for d in sorted(Path("vendor").glob("*/Cargo.toml")):
    l = tomllib.loads(d.read_text())["package"].get("license")
    if not l:
        raise SystemExit(f"ERROR: no license field in {d}")
    lics.append(l)

out = []
for l in lics:
    for t in atoms(l):
        if t not in out:
            out.append(t)

# Project license first, rest sorted.
order = [t for t in atoms(lics[0]) if t in out]
order += sorted(t for t in out if t not in order)
print(" AND ".join(order))
PY
}

# Source1: vendored deps + .cargo redirect config. The bundled crate
# provides are emitted at build time by the cargo_vendor fileattr hook
# (cargo-rpm-macros) from the shipped cargo-vendor.txt.
make_vendor_sources() {
    rm -rf vendor .cargo
    cargo vendor vendor/
    mkdir -p .cargo
    cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor/"
EOF
    tar cJf "${RPM_TOP}/SOURCES/${NAME}-${VERSION}-vendor.tar.xz" vendor .cargo
}

# Verify the spec's Version:, Cargo.toml version, and License: are up to date.
check_spec() {
    local current reported cver
    current="$(sed -n 's/^Version:[[:space:]]*//p' "$SPEC")"
    if [[ -z "$current" || "$current" != "$VERSION" ]]; then
        echo "ERROR: spec Version ($current) does not match $VERSION."
        echo "Update 'Version:' in $SPEC."
        return 1
    fi
    cver="$(python3 -c 'import tomllib;print(tomllib.load(open("Cargo.toml","rb"))["package"]["version"])')"
    if [[ "$cver" != "$VERSION" ]]; then
        echo "ERROR: Cargo.toml version ($cver) does not match $VERSION."
        echo "Update 'version' in Cargo.toml."
        return 1
    fi
    reported="$(license_expression)"
    current="$(sed -n 's/^License:[[:space:]]*//p' "$SPEC")"
    if [[ -z "$current" || "$current" != "$reported" ]]; then
        echo "ERROR: License tag out of date."
        echo "  spec:     $current"
        echo "  reported: $reported"
        echo "Update 'License:' in $SPEC."
        return 1
    fi
    echo "OK: spec Version ($VERSION) and License are up to date"
}

do_sources() {
    # Drop artifacts of previous builds (topdir is persistent and shared).
    rm -f "${RPM_TOP}/RPMS"/*/${NAME}-*.rpm \
         "${RPM_TOP}/SRPMS/${NAME}"-*.src.rpm
    cp "$SPEC" "${RPM_TOP}/SPECS/"
    # Source0: archive from HEAD (Fedora-preferred .tar.xz compression).
    git archive --prefix="${NAME}-${VERSION}/" HEAD | xz -f \
        > "${RPM_TOP}/SOURCES/${NAME}-${VERSION}.tar.xz"
    make_vendor_sources
    check_spec
    rm -rf vendor .cargo
    echo "Sources ready in ${RPM_TOP}/SOURCES:"
    ls -l "${RPM_TOP}/SOURCES"
}

do_build() {
    do_sources
    # release_number() must run from the repo (git describe); the rpmbuild
    # subshell has SPECS as its cwd.
    local release
    release="$(release_number)"
    echo "==> Release number: $release (commits since last tag + 1)"
    ( cd "${RPM_TOP}/SPECS" && rpmbuild --define "_topdir ${RPM_TOP}" --define "release $release" -ba "$SPEC" )
}

# Lint the spec (from SPECS) and the built binary RPMs.
do_lint() {
    ( cd "${RPM_TOP}/SPECS" && rpmlint "$SPEC" )
    rpmlint "${RPM_TOP}/RPMS"/*/${NAME}*.rpm
}

echo "==> Building RPM for $NAME v$VERSION"
do_build
echo "==> Done"
ls -lh "${RPM_TOP}"/RPMS/*/${NAME}*.rpm

case "${1:-}" in
    lint) do_lint ;;
    "") ;;
    *) echo "Usage: $0 [lint]" >&2; exit 2 ;;
esac
