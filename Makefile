SHELL := /bin/bash

# curl -il -X GET  http://localhost:8080/v1/test

# ==============================================================================
# Local support

scratch:
	go run app/tooling/scratch/main.go


up:
	go run app/services/node/main.go -race | go run app/tooling/logfmt/main.go

up2:
	go run app/services/node/main.go -race --web-debug-host 0.0.0.0:7181 --web-public-host 0.0.0.0:8180 --web-private-host 0.0.0.0:9180 --node-miner-name=miner2 --node-db-path zblock/blocks2.db | go run app/tooling/logfmt/main.go

down:
	kill -INT $(shell ps | grep "main -race" | grep -v grep | sed -n 1,1p | cut -c1-5)

# ==============================================================================
# Modules support

tidy:
	go mod tidy
	go mod vendor
