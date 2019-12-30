NAME := cxray

.PHONY: build
build:
	GOOS=linux GOARCH=amd64 go build -o build/cxray cmd/cxray.go

lint:
	golint -set_exit_status $$(go list ./...)

test:
	go test -v ./...
