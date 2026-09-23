FROM golang:1.27.1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcpwarden ./cmd/mcpwarden

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcpwarden /mcpwarden
WORKDIR /data
EXPOSE 8787
ENTRYPOINT ["/mcpwarden"]
