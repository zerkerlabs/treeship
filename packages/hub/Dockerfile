FROM golang:1.22-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o hub .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

# Install treeship CLI (needed by /v1/verify endpoint)
ARG TREESHIP_VERSION=0.1.0
RUN curl -fsSL "https://github.com/zerkerlabs/treeship/releases/download/v${TREESHIP_VERSION}/treeship-linux-x86_64" \
    -o /usr/local/bin/treeship && chmod +x /usr/local/bin/treeship

COPY --from=builder /app/hub /usr/local/bin/hub

EXPOSE 8080
CMD ["hub"]
