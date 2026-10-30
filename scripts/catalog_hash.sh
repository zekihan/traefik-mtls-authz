#!/usr/bin/env bash
# Print a release-note snippet for the exact archive Traefik's catalog serves.
# Run after tagging and catalog indexing. This script does not publish or edit a release.
set -euo pipefail
version=${1:?usage: scripts/catalog_hash.sh v0.1.1}
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo 'expected a vMAJOR.MINOR.PATCH tag' >&2
  exit 1
fi
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  "https://plugins.traefik.io/public/download/github.com/zekihan/traefik-mtls-authz/$version" \
  --output "$archive"
hash=$(sha256sum "$archive")
printf 'Catalog archive (%s) SHA-256: `%s`\n' "$version" "${hash%% *}"
