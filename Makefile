.PHONY: install setup check-demo build test demo offline clean

# Installs exact package versions from the lockfile, plus the Go modules.
install:
	npm ci
	cd backend && go mod download

# Compiles the circuit and runs the Groth16 setup. Only needed when the circuit changes.
setup:
	bash scripts/check-prereqs.sh setup
	bash scripts/setup.sh

check-demo:
	bash scripts/check-prereqs.sh demo

build:
	cd backend && go build -o ../bin/ ./cmd/...
	npx tsc -p frontend/tsconfig.json
	npx vite build frontend

test: check-demo build
	cd backend && go test ./...
	node --disable-warning=ExperimentalWarning --test scripts/circuit.test.mjs

demo: check-demo build
	bash scripts/run.sh

# Verifies the latest proof from Pinecrest Apps with no network at all.
offline:
	bash scripts/verify-offline.sh

# Deletes generated keys and logs, keeping the circuit setup. Credentials already
# in a browser wallet stop working, because the issuer key changes.
clean:
	rm -rf bin frontend/dist logs data/state data/trustee data/site-a data/site-b
