SHELL=/bin/bash -o pipefail

.PHONY: format
format:
	cargo +nightly fmt

.PHONY: build
build:
	cargo +nightly build --target=wasm32-unknown-unknown --release
