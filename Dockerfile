# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/authcell ./cmd/api

# Distroless: no shell, runs as an unprivileged user, ships CA certs for TLS to Postgres.
FROM gcr.io/distroless/static-debian12:nonroot AS prod
COPY --from=build /out/authcell /authcell
ENV PORT=8080
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 CMD ["/authcell", "-healthcheck"]
ENTRYPOINT ["/authcell"]
