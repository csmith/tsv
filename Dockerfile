FROM golang:1.25.2 AS build
WORKDIR /go/src/app
COPY . .

RUN set -eux; \
    CGO_ENABLED=0 GO111MODULE=on go install .; \
    go run github.com/google/go-licenses@latest save ./... --save_path=/notices; \
    mkdir -p /mounts/config;

FROM ghcr.io/greboid/dockerbase/nonroot:1.20250803.0
COPY --from=build /go/bin/tsv /tsv
COPY --from=build /notices /notices
COPY --from=build --chown=65532:65532 /mounts /
VOLUME /config
ENTRYPOINT ["/tsv", "--tailscale-config-dir=/config"]
