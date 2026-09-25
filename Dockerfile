ARG FILESTASH_COMMIT=426bb93b2b93f68d8abf378302228ca5e7e51898
ARG GO_OIDC_VERSION=v3.21.0

FROM golang:1.26-trixie@sha256:bdca99a00bc16590cb1a0bb4e698f5fc5d6a64e4d5eef13d9f18a0ee08e5fa65 AS source
ARG FILESTASH_COMMIT
ARG GO_OIDC_VERSION
WORKDIR /home/filestash/
RUN git init -q . && \
    git remote add origin https://github.com/mickael-kerjean/filestash && \
    git fetch -q --depth 1 origin ${FILESTASH_COMMIT} && \
    git checkout -q FETCH_HEAD
RUN --mount=type=cache,target=/go/pkg/mod \
    go get github.com/coreos/go-oidc/v3@${GO_OIDC_VERSION}
RUN sed -i '/plugin\/plg_authenticate_local"/a\	_ "github.com/mickael-kerjean/filestash/server/plugin/plg_authenticate_oidc"' server/plugin/index.go && \
    grep -q plg_authenticate_oidc server/plugin/index.go

FROM source AS test
RUN --mount=type=cache,target=/go/pkg/mod \
    go generate ./server/pkg/env/
COPY plg_authenticate_oidc/ server/plugin/plg_authenticate_oidc/
ENV CGO_ENABLED=0 FILESTASH_PATH=/tmp/filestash
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    ! gofmt -l server/plugin/plg_authenticate_oidc/ | grep . && \
    go vet ./server/plugin/plg_authenticate_oidc/ && \
    go test -count=1 ./server/plugin/plg_authenticate_oidc/

FROM golang:1.26-trixie@sha256:bdca99a00bc16590cb1a0bb4e698f5fc5d6a64e4d5eef13d9f18a0ee08e5fa65 AS build
RUN apt-get update > /dev/null && \
    apt-get install -y curl make > /dev/null 2>&1 && \
    apt-get install -y libjpeg-dev libtiff-dev libpng-dev libwebp-dev libraw-dev libheif-dev libgif-dev libvips-dev > /dev/null 2>&1 && \
    apt-get install -y libavcodec-dev libavdevice-dev libavfilter-dev libavformat-dev libswresample-dev libswscale-dev libavutil-dev > /dev/null 2>&1
WORKDIR /home/filestash/
COPY --from=source /home/filestash/ .
COPY plg_authenticate_oidc/ server/plugin/plg_authenticate_oidc/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    make init && \
    make build

FROM debian:stable-slim@sha256:5bc3287b25407c965a30f38e32603dc253a3869e1b12a21ac09bfc27fd8b13ce
LABEL org.opencontainers.image.title="filestash-oidc-plugin" \
      org.opencontainers.image.description="Filestash with OpenID Connect sign-in and group based directories" \
      org.opencontainers.image.source="https://github.com/islpriem/filestash-oidc-plugin" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
WORKDIR /app/
COPY --from=build /home/filestash/dist/ .
RUN apt-get update > /dev/null && \
    apt-get -y upgrade > /dev/null && \
    apt-get install -y --no-install-recommends ca-certificates curl ffmpeg libbrotli1 poppler-utils && \
    useradd filestash && \
    mkdir -p /app/data/state/ && \
    chown -R filestash:filestash /app/ && \
    chmod 730 /app/filestash && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/*

USER filestash
CMD ["/app/filestash"]
EXPOSE 8334
