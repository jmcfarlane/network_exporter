debug: tidy
	go run main.go -debug=true

run: tidy
	go run main.go

tidy:
	go mod tidy

install:
	go install

