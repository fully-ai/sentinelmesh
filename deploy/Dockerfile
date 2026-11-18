FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentinelmesh-server ./cmd/sentinelmesh-server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentinelmesh ./cmd/sentinelmesh

FROM alpine:3.21
RUN adduser -D -u 10001 sentinel && mkdir -p /data && chown sentinel:sentinel /data
USER sentinel
WORKDIR /data
COPY --from=builder /out/sentinelmesh-server /usr/local/bin/sentinelmesh-server
COPY --from=builder /out/sentinelmesh /usr/local/bin/sentinelmesh
EXPOSE 8440
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD wget -qO- http://127.0.0.1:8440/api/v1/health || exit 1
ENTRYPOINT ["/usr/local/bin/sentinelmesh-server"]
CMD ["-addr", "0.0.0.0:8440", "-db", "/data/sentinelmesh.db"]
