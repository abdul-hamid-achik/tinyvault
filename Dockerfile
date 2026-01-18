# Build stage
FROM golang:alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the server binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/server ./cmd/server

# Build the CLI binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/tvault ./cmd/tvault

# Final stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 tinyvault && \
    adduser -u 1000 -G tinyvault -s /bin/sh -D tinyvault

WORKDIR /app

# Copy binaries
COPY --from=builder /bin/server /app/server
COPY --from=builder /bin/tvault /usr/local/bin/tvault

# Copy static assets
COPY --from=builder /app/web/static /app/web/static

# Set ownership
RUN chown -R tinyvault:tinyvault /app

USER tinyvault

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/server"]
