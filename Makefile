.PHONY: tidy lint test test/cover

tidy:
	gofmt -w *.go
	go mod tidy

lint:
	go vet ./...

test:
	go test -race ./...

test/cover:
	go test -race -coverprofile=coverage.out ./...
