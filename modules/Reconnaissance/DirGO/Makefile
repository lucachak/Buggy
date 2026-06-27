BINARY=DirGo
MAIN=cmd/dirpy/main.go

.PHONY: all build clean test run

all: build

build:
	go build -ldflags="-s -w" -o $(BINARY) $(MAIN)

build-all:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-linux-amd64 $(MAIN)
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BINARY)-linux-arm64 $(MAIN)
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-darwin-amd64 $(MAIN)
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BINARY)-darwin-arm64 $(MAIN)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-windows-amd64.exe $(MAIN)

test:
	go test ./...

run:
	go run $(MAIN) -u http://localhost:8000/

clean:
	rm -f $(BINARY) $(BINARY)-*