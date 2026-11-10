# Shared version and ref handling for the release scripts.
valid_release_version() {
    case "$1" in ''|*[!0123456789.]*) return 1 ;; esac
    printf '%s\n' "$1" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
}

release_tags() {
    git ls-remote --tags origin 'refs/tags/v*-modern' 'refs/tags/v*-modern^{}'
}

latest_release_version() {
    sed -nE 's@.*refs/tags/v([0-9]+\.[0-9]+\.[0-9]+)-modern$@\1@p' | sort -V | tail -n 1
}

release_ref_commit() {
    awk -v ref="$1" '
        $2 == ref { direct=$1 }
        $2 == ref "^{}" { peeled=$1 }
        END { print peeled ? peeled : direct }'
}

release_staging_ref() {
    printf 'refs/heads/ci/release-%s\n' "${GITHUB_RUN_ID:?}"
}
