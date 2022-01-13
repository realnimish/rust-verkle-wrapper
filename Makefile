DIR := $(shell pwd)
PATH := $(DIR)/osxcross/target/bin:$(PATH)

all: setup-env build-all

build-all: build-osx build-linux build-windows build-linux-arm build-linux-arm64

build-osx:
	rustup target add x86_64-apple-darwin
	cargo build --target=x86_64-apple-darwin --release

build-linux:
	rustup target add x86_64-unknown-linux-gnu
	cargo build --target=x86_64-unknown-linux-gnu --release

build-windows:
	rustup target add x86_64-pc-windows-gnu
	rustup toolchain install stable-x86_64-pc-windows-gnu
	cargo build --target=x86_64-pc-windows-gnu --release

build-linux-arm:
	rustup target add arm-unknown-linux-gnueabi
	cargo build --target=arm-unknown-linux-gnueabi --release

build-linux-arm64:
	rustup target add aarch64-unknown-linux-gnu
	cargo build --target=aarch64-unknown-linux-gnu --release

setup-env:
	sh setup.sh

clean:
#	rm -rf target
#	rm -rf build
#	rm -rf Cargo.lock
#	rm -rf osxcross
#	rm -rf runtimes