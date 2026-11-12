#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. scripts/release-common.sh

source=$(git rev-parse HEAD)
if [ "$GITHUB_EVENT_NAME" != workflow_dispatch ] || [ "$GITHUB_REF" != refs/heads/master ] ||
   [ "$PUBLISH_REQUESTED" != true ] || [ "$source" != "$GITHUB_SHA" ]; then
    echo 'Manual release preparation requires a publish dispatch from master' >&2
    exit 1
fi

version=${REQUESTED_RELEASE_VERSION:?}
base=$(cat VERSION)
if ! valid_release_version "$version" || ! valid_release_version "$base"; then
    echo 'release_version and VERSION must contain MAJOR.MINOR.PATCH' >&2
    exit 1
fi
if ! dpkg --compare-versions "$version" gt "$base"; then
    printf 'release_version must be newer than the selected master VERSION (%s)\n' "$base" >&2
    exit 1
fi

stage=$(release_staging_ref)
stage_refs=$(git ls-remote origin "$stage")
prepared=$(printf '%s\n' "$stage_refs" | release_ref_commit "$stage")
if [ -n "$prepared" ]; then
    # A retry of this run must reuse the staged commit and its package artifacts.
    git fetch --depth=2 origin "$stage"
    if [ "$(git rev-parse FETCH_HEAD)" != "$prepared" ] ||
       [ "$(git show -s --format=%P "$prepared")" != "$source" ] ||
       [ "$(git diff --name-only --no-renames "$source" "$prepared" --)" != VERSION ] ||
       [ "$(git show "$prepared:VERSION")" != "$version" ]; then
        printf 'Staging ref %s does not match the requested release\n' "$stage" >&2
        exit 1
    fi
fi

refs=$(release_tags)
latest=$(printf '%s\n' "$refs" | latest_release_version)
target=$(printf '%s\n' "$refs" | release_ref_commit "refs/tags/v$version-modern")
if [ -n "$target" ]; then
    if [ "$target" != "$prepared" ]; then
        printf 'Tag v%s-modern already belongs to another commit\n' "$version" >&2
        exit 1
    fi
elif [ -n "$latest" ] && ! dpkg --compare-versions "$version" gt "$latest"; then
    printf 'release_version must be newer than the highest release tag (%s)\n' "$latest" >&2
    exit 1
fi

if [ -z "$prepared" ]; then
    printf '%s\n' "$version" > VERSION
    git -c user.name='github-actions[bot]' \
        -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
        commit -m "Release dnsp-modern $version" -- VERSION
    prepared=$(git rev-parse HEAD)
    git push --force-with-lease="$stage:" origin "$prepared:$stage"
fi
printf 'Prepared %s at %s\n' "$prepared" "$stage"
printf 'commit=%s\n' "$prepared" >> "${GITHUB_OUTPUT:?}"
