FROM golang:1.26-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build info for /v1/version. `railway up` builds without a .git directory,
# so pass these as build args when you can:
#   docker build --build-arg HUB_VERSION=0.31.10 --build-arg HUB_COMMIT=$(git rev-parse --short HEAD) \
#     --build-arg HUB_BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ) .
# Unset, the endpoint reports "dev" / "unknown" rather than guessing.
ARG HUB_VERSION=""
ARG HUB_COMMIT=""
ARG HUB_BUILT_AT=""
RUN CGO_ENABLED=1 go build \
    -ldflags "-X github.com/zerkerlabs/treeship/packages/hub/internal/version.Version=${HUB_VERSION} -X github.com/zerkerlabs/treeship/packages/hub/internal/version.Commit=${HUB_COMMIT} -X github.com/zerkerlabs/treeship/packages/hub/internal/version.BuiltAt=${HUB_BUILT_AT}" \
    -o hub .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

# Persistent data directory for SQLite.
# On Railway, attach a volume mounted at /var/lib/treeship.
RUN mkdir -p /var/lib/treeship && chmod 755 /var/lib/treeship

COPY --from=builder /app/hub /usr/local/bin/hub

EXPOSE 8080
CMD ["hub"]
