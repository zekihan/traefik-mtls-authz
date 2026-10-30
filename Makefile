.PHONY: tidy lint test test/cover test/integration check/docs

tidy:
	gofmt -w *.go testing/*.go
	go mod tidy

lint:
	test -z "$$(gofmt -l testing)"
	go vet ./...
	go vet -tags integration ./testing

test:
	go test -race ./...

test/cover:
	go test -race -coverprofile=coverage.out ./...

check/docs:
	python3 scripts/check_docs_yaml.py

# Requires Linux, Docker Engine and Docker Compose v2; creates no production resources.
test/integration:
	go test -race -tags integration -count=1 -timeout=10m -v ./testing
