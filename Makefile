VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
TEST_DB ?= postgres://authcell:authcell@localhost:5432/authcell?sslmode=disable

.PHONY: all build run test itest lint clean watch docker-run docker-down

all: lint test build

build:
	@echo "Building $(VERSION)..."
	@CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o main ./cmd/api

run:
	@go run ./cmd/api

# Unit tests only. Integration tests skip without a database.
test:
	@go test -race ./...

# Unit + integration tests against a real Postgres (start one with `make docker-run`).
itest:
	@AUTHCELL_TEST_DATABASE_URL="$(TEST_DB)" go test -race -count=1 ./...

lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	@go vet ./...

clean:
	@rm -f main
	@rm -rf tmp dist

docker-run:
	@docker compose up --build

docker-down:
	@docker compose down

watch:
	@command -v air >/dev/null 2>&1 || go install github.com/air-verse/air@latest
	@air
