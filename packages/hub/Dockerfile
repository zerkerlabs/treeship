FROM golang:1.22-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o hub .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

# Persistent data directory for SQLite. Railway volume should mount here.
RUN mkdir -p /var/lib/treeship && chmod 755 /var/lib/treeship
VOLUME ["/var/lib/treeship"]

COPY --from=builder /app/hub /usr/local/bin/hub

EXPOSE 8080
CMD ["hub"]
