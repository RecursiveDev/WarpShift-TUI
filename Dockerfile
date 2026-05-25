# ---- Build Stage ----
FROM golang:1.26-alpine AS build

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG VERSION
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION:-dev}" \
    -o /out/warpshift ./cmd/warpshift

# ---- Runtime Stage ----
FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S warpshift && \
    adduser -S warpshift -G warpshift && \
    rm -rf /var/cache/apk/*

COPY --from=build --chown=warpshift:warpshift /out/warpshift /usr/local/bin/warpshift

USER warpshift
WORKDIR /home/warpshift

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD warpshift version > /dev/null 2>&1 || exit 1

STOPSIGNAL SIGTERM

ENTRYPOINT ["warpshift"]
