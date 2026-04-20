FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/quic-link .

FROM alpine:3.23

RUN apk add --no-cache ca-certificates && adduser -D -g '' app

WORKDIR /app
COPY --from=builder /out/quic-link /app/quic-link

USER app

ENTRYPOINT ["/app/quic-link"]
