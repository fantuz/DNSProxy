#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

base=$(cat VERSION)
if ! printf '%s\n' "$base" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo "VERSION must contain MAJOR.MINOR.PATCH" >&2
    exit 1
fi
tag="v$base-modern"
commit=$(git rev-parse HEAD)
mode=snapshot
case "$GITHUB_REF" in
    refs/tags/*)
        if [ "$GITHUB_EVENT_NAME" != push ] || [ "$GITHUB_REF" != "refs/tags/$tag" ]; then
            echo "Push the release tag matching VERSION ($tag)" >&2
            exit 1
        fi
        mode=tag
        ;;
    refs/heads/master)
        if [ "$GITHUB_EVENT_NAME" = push ] || [ "${PUBLISH_REQUESTED:-false}" = true ]; then
            refs=$(git ls-remote --tags origin 'refs/tags/v*-modern' 'refs/tags/v*-modern^{}')
            previous=$(printf '%s\n' "$refs" | sed -nE 's@.*refs/tags/v([0-9]+\.[0-9]+\.[0-9]+)-modern$@\1@p' | sort -V | tail -n 1)
            target=$(printf '%s\n' "$refs" | awk -v ref="refs/tags/$tag" '
                $2 == ref { direct=$1 }
                $2 == ref "^{}" { peeled=$1 }
                END { print peeled ? peeled : direct }')
            if [ -z "$previous" ] || dpkg --compare-versions "$base" gt "$previous" ||
               { [ "$base" = "$previous" ] && [ "$commit" = "$target" ]; }; then
                mode=master
            else
                printf 'VERSION %s has no new release beyond %s\n' "$base" "$previous"
            fi
        fi
        ;;
    *)
        if [ "${PUBLISH_REQUESTED:-false}" = true ]; then
            echo "Manual publication requires master" >&2
            exit 1
        fi
        ;;
esac

version=$base
if [ "$mode" = snapshot ]; then
    version="$base~pre${GITHUB_RUN_NUMBER:?}.ci"
fi
{
    printf 'version=%s\n' "$version"
    printf 'tag=%s\n' "$tag"
    printf 'mode=%s\n' "$mode"
    printf 'commit=%s\n' "$commit"
} >> "${GITHUB_OUTPUT:?}"
