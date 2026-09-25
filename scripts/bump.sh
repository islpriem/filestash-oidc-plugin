#!/bin/sh
# Moves the Dockerfile to the latest Filestash commit, go-oidc release and base
# image digests. Base image tags stay as they are; bumping Go is done by hand.
set -eu
cd "$(dirname "$0")/.."

filestash=$(git ls-remote https://github.com/mickael-kerjean/filestash HEAD | cut -f1)
oidc=$(curl -fsS https://proxy.golang.org/github.com/coreos/go-oidc/v3/@latest | sed -n 's/.*"Version":"\([^"]*\)".*/\1/p')
[ -n "$filestash" ]
[ -n "$oidc" ]
sed -i.bak \
    -e "s/^ARG FILESTASH_COMMIT=.*/ARG FILESTASH_COMMIT=$filestash/" \
    -e "s/^ARG GO_OIDC_VERSION=.*/ARG GO_OIDC_VERSION=$oidc/" \
    Dockerfile

for image in $(sed -n 's/^FROM \([^@ ]*\)@sha256:.*/\1/p' Dockerfile | sort -u); do
    digest=$(docker buildx imagetools inspect "$image" | awk '/^Digest:/ { print $2 }')
    [ -n "$digest" ]
    sed -i.bak "s|^FROM $image@sha256:[0-9a-f]*|FROM $image@$digest|" Dockerfile
done
rm -f Dockerfile.bak
