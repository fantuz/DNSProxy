#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. scripts/release-common.sh

base=$(cat VERSION)
if ! valid_release_version "$base"; then
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
        if [ -n "${REQUESTED_RELEASE_VERSION:-}" ]; then
            if [ "$GITHUB_EVENT_NAME" != workflow_dispatch ] || [ "${PUBLISH_REQUESTED:-false}" != true ] ||
               [ "$base" != "$REQUESTED_RELEASE_VERSION" ] || [ "$commit" != "${PREPARED_RELEASE_COMMIT:-}" ]; then
                echo 'release_version requires publish and a matching prepared release commit' >&2
                exit 1
            fi
            mode=manual
        elif [ "$GITHUB_EVENT_NAME" = push ] || [ "${PUBLISH_REQUESTED:-false}" = true ]; then
            refs=$(release_tags)
            previous=$(printf '%s\n' "$refs" | latest_release_version)
            target=$(printf '%s\n' "$refs" | release_ref_commit "refs/tags/$tag")
            if [ -z "$previous" ] || dpkg --compare-versions "$base" gt "$previous" ||
               { [ "$base" = "$previous" ] && [ "$commit" = "$target" ]; }; then
                mode=master
            else
                printf 'VERSION %s has no new release beyond %s\n' "$base" "$previous"
            fi
        fi
        ;;
    *)
        if [ "${PUBLISH_REQUESTED:-false}" = true ] || [ -n "${REQUESTED_RELEASE_VERSION:-}" ]; then
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
