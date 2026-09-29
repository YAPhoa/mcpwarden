FROM golang:1.27.1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/mcpwarden ./cmd/mcpwarden-security-db

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcpwarden /out/mcpwarden-security-db /
WORKDIR /data
EXPOSE 8787
ENTRYPOINT ["/mcpwarden"]
