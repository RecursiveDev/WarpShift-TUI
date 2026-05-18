# ---- Build Stage ----
FROM golang:1.24-alpine AS build

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION:-dev}" \
    -o /out/warpshift ./cmd/warpshift

# ---- Runtime Stage ----
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S warpshift && \
    adduser -S warpshift -G warpshift

COPY --from=build /out/warpshift /usr/local/bin/warpshift

USER warpshift
WORKDIR /home/warpshift

HEALTHCHECK --interval=30s --timeout=3s --retries=3 --start-period=5s \
    CMD pgrep warpshift || exit 1

ENTRYPOINT ["warpshift"]
