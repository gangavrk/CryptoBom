# Build stage: cgo is required (the Java analyzer links tree-sitter).
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/cryptobom ./cmd/cryptobom

# Runtime stage: slim glibc base (the cgo binary is dynamically linked).
FROM debian:bookworm-slim
COPY --from=build /out/cryptobom /usr/local/bin/cryptobom
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
