# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /proton-carddav ./cmd/proton-carddav

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /proton-carddav /proton-carddav
EXPOSE 8080
ENTRYPOINT ["/proton-carddav"]
