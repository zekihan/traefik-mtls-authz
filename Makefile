.PHONY: tidy lint test test/cover check/docs

tidy:
	gofmt -w *.go
	go mod tidy

lint:
	go vet ./...

test:
	go test -race ./...

test/cover:
	go test -race -coverprofile=coverage.out ./...

check/docs:
	python3 scripts/check_docs_yaml.py
