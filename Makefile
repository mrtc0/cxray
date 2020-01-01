NAME := cxray

.PHONY: build test
build:
	GOOS=linux GOARCH=amd64 go build -o build/cxray cmd/cxray.go

lint:
	golint -set_exit_status $$(go list ./...)

test:
	sudo go test -v ./...
