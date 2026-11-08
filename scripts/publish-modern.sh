#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(cat VERSION)
tag="v${version}-modern"
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

if draft=$(gh release view "$tag" --json isDraft --jq .isDraft 2>/dev/null); then
    if [[ "$draft" = false ]]; then
        echo "$tag is already published"
        exit 0
    fi
    echo "An incomplete draft already exists for $tag. Review it before retrying." >&2
    exit 1
fi

cd - >/dev/null
ref=$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")
if [[ -z "$ref" && "$RELEASE_MODE" = master ]]; then
    # Claim the tag only once the complete asset set has passed validation.
    # A normal git push refuses to replace an existing tag.
    git push origin "$RELEASE_COMMIT:refs/tags/$tag"
    ref=$(git ls-remote --exit-code origin "refs/tags/$tag" "refs/tags/$tag^{}")
fi
target=$(awk -v ref="refs/tags/$tag" '
    $2 == ref { direct=$1 }
    $2 == ref "^{}" { peeled=$1 }
    END { print peeled ? peeled : direct }' <<< "$ref")
if [[ "$target" != "$RELEASE_COMMIT" ]]; then
    echo "$tag does not point to the tested commit" >&2
    exit 1
fi

cd "$assets"
gh release create "$tag" "${packages[@]}" SHA256SUMS --verify-tag \
    --title "DNSProxy Modern $version" --prerelease --generate-notes
