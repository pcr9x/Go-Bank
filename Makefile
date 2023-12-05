build:
	@go build -o bin/GoBank

run: build
	@./bin/GoBank

test:
	@go test -v ./...