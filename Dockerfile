FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /proton-sync ./cmd/proton-sync

FROM alpine:3.20
RUN addgroup -S sync && adduser -S -G sync sync
USER sync
WORKDIR /data
COPY --from=build /proton-sync /usr/local/bin/proton-sync
VOLUME ["/data"]
ENTRYPOINT ["proton-sync"]
CMD ["daemon"]
