#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/release-common.sh

version=$(cat VERSION)
tag="v${version}-modern"
tag_ref="refs/tags/$tag"
if [[ "$RELEASE_TAG" != "$tag" || "$RELEASE_COMMIT" != "$(git rev-parse HEAD)" ]]; then
    echo "Release plan does not match the checked-out version and commit" >&2
    exit 1
fi

case "$RELEASE_MODE" in
    master)
        master=$(git ls-remote --exit-code origin refs/heads/master)
        if [[ "${master%%$'\t'*}" != "$RELEASE_COMMIT" ]]; then
            echo "A newer master build will handle publication"
            exit 0
        fi
        ;;
    manual)
        if [[ "$GITHUB_EVENT_NAME" != workflow_dispatch || "$GITHUB_REF" != refs/heads/master ]]; then
            echo 'Manual publication requires a dispatch from master' >&2
            exit 1
        fi
        stage=$(release_staging_ref)
        ;;
    tag) ;;
    *) echo "Invalid release mode" >&2; exit 1 ;;
esac

assets=$(realpath "$1")
cd "$assets"
packages=()
for distro in ubuntu22.04 ubuntu24.04 debian13; do
    for arch in amd64 arm64; do
        packages+=("dnsp-modern_${version}+${distro}_${arch}.deb")
    done
done
for arch in x86_64 aarch64; do
    packages+=("dnsp-modern-${version}-1.el9.${arch}.rpm")
done
shopt -s nullglob
present=(*.deb *.rpm)
if (( ${#present[@]} != ${#packages[@]} )); then
    echo "Expected ${#packages[@]} packages, found ${#present[@]}" >&2
    exit 1
fi
for pkg in "${packages[@]}"; do
    if [[ ! -s "$pkg" ]]; then
        echo "Missing release package $pkg" >&2
        exit 1
    fi
done
sha256sum "${packages[@]}" > SHA256SUMS
sha256sum -c SHA256SUMS

cd - >/dev/null
refs=$(release_tags)
target=$(release_ref_commit "$tag_ref" <<< "$refs")
if draft=$(gh release view "$tag" --json isDraft --jq .isDraft 2>/dev/null); then
    if [[ "$draft" != false ]]; then
        echo "An incomplete draft already exists for $tag. Review it before retrying." >&2
        exit 1
    fi
else
    draft=
    if [[ -z "$target" && "$RELEASE_MODE" != tag ]]; then
        if [[ "$RELEASE_MODE" == manual ]]; then
            latest=$(latest_release_version <<< "$refs")
            if [[ -n "$latest" ]] && ! dpkg --compare-versions "$version" gt "$latest"; then
                echo "A newer release tag already exists ($latest)" >&2
                exit 1
            fi
            staged=$(git ls-remote origin "$stage")
            if [[ "$(release_ref_commit "$stage" <<< "$staged")" != "$RELEASE_COMMIT" ]]; then
                echo "Staging ref $stage does not point to the tested commit" >&2
                exit 1
            fi
        fi

        # Claim the tag only after validating the complete asset set.
        git push origin "$RELEASE_COMMIT:$tag_ref"
        refs=$(git ls-remote --exit-code origin "$tag_ref" "$tag_ref^{}")
        target=$(release_ref_commit "$tag_ref" <<< "$refs")
    fi
fi
if [[ "$target" != "$RELEASE_COMMIT" ]]; then
    echo "$tag does not point to the tested commit" >&2
    exit 1
fi

if [[ "$draft" = false ]]; then
    echo "$tag is already published"
else
    (
        cd "$assets"
        gh release create "$tag" "${packages[@]}" SHA256SUMS --verify-tag \
            --title "DNSProxy Modern $version" --prerelease=false --generate-notes
    )
fi

if [[ "$RELEASE_MODE" == manual ]]; then
    staged=$(git ls-remote origin "$stage")
    if [[ -n "$staged" ]]; then
        git push --force-with-lease="$stage:$RELEASE_COMMIT" origin ":$stage"
    fi
fi
