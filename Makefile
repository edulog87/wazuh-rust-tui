# Makefile for wazuh-tui

BINARY_NAME=wazuh-rust-tui
INSTALL_DIR=/usr/local/bin

.PHONY: all install build clean test run check fmt lint doc help

all: build

help:
	@echo "Available targets:"
	@echo "  build    - Build release binary"
	@echo "  run      - Build and run the application"
	@echo "  test     - Run all tests"
	@echo "  check    - Run clippy linter"
	@echo "  fmt      - Format code with rustfmt"
	@echo "  lint     - Run both fmt check and clippy"
	@echo "  doc      - Generate documentation"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install binary to $(INSTALL_DIR) (requires sudo)"

build:
	cargo build --release
	@cp target/release/$(BINARY_NAME) . 2>/dev/null || true
	@echo "Build complete: ./$(BINARY_NAME)"

run: build
	./$(BINARY_NAME)

install: build
	sudo cp target/release/$(BINARY_NAME) $(INSTALL_DIR)/wazuh-tui
	@echo "Installed to $(INSTALL_DIR)/wazuh-tui"

clean:
	cargo clean
	rm -f $(BINARY_NAME)

test:
	cargo test

test-all:
	cargo test -- --include-ignored

check:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

lint: fmt-check check

doc:
	cargo doc --no-deps --open
