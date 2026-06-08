FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /proton-sync ./cmd/proton-sync

# 'sync' is a BusyBox built-in command; using it as a group/user name
# causes `addgroup -S sync` to exit 1 on Alpine. Use appgroup/appuser.
FROM alpine:3.20
RUN addgroup -S appgroup && adduser -S -G appgroup appuser
USER appuser
WORKDIR /data
COPY --from=build /proton-sync /usr/local/bin/proton-sync
VOLUME ["/data"]
ENTRYPOINT ["proton-sync"]
CMD ["daemon"]
