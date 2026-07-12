.PHONY: build test vet run-cp run-agent docker clean

build:
	go build -o bin/ ./cmd/...

test:
	go test ./...

vet:
	go vet ./...

run-cp: build
	./bin/controlplane -config deploy/controlplane.example.json

run-agent: build
	./bin/agent -config deploy/agent.example.json -once

docker:
	cd deploy && docker compose up --build

clean:
	rm -rf bin data
