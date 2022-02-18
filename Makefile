DIR := $(shell pwd)

all: build-all

build-all: build-osx build-linux build-windows build-linux-arm build-linux-arm64
build-linux-all: build-linux build-linux-arm build-linux-arm64

build-osx:
	rustup default nightly
	cargo build  --release

build-linux:
	rustup default nightly
	rustup target add x86_64-unknown-linux-gnu
	cargo build --target=x86_64-unknown-linux-gnu --release

build-windows:
	rustup default nightly
	cargo build --release

build-linux-arm:
	rustup default nightly
	rustup target add arm-unknown-linux-gnueabi
	cargo build --target=arm-unknown-linux-gnueabi --release

build-linux-arm64:
	rustup default nightly
	rustup target add aarch64-unknown-linux-gnu
	cargo build --target=aarch64-unknown-linux-gnu --release

clean:
#	rm -rf target
#	rm -rf build
#	rm -rf Cargo.lock
#	rm -rf osxcross
#	rm -rf runtimes