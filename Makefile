DIR := $(shell pwd)

all: build-all

build-all: build-osx build-linux build-windows build-linux-arm build-linux-arm64
build-linux-all: build-linux build-linux-arm build-linux-arm64

build-osx:
	rustup default nightly
	cargo build

build-linux:
	rustup default nightly
	rustup target add x86_64-unknown-linux-gnu
	cargo build --target=x86_64-unknown-linux-gnu

build-windows:
	rustup default nightly
	cargo build

build-linux-arm:
	rustup default nightly
	rustup target add arm-unknown-linux-gnueabi
	cargo build --target=arm-unknown-linux-gnueabi

build-linux-arm64:
	rustup default nightly
	rustup target add aarch64-unknown-linux-gnu
	cargo build --target=aarch64-unknown-linux-gnu

osx-dir:
	@mkdir -p runtimes/osx-arm64/native
	@mkdir -p runtimes/osx-x64/native
	@cp ./target/release/librust_verkle.dylib ./runtimes/osx-arm64/native/.
	@cp ./target/release/librust_verkle.dylib ./runtimes/osx-x64/native/.

win-dir:
	@mkdir -p runtimes/win-x64/native
	@cp ./target/release/rust_verkle.dll ./runtimes/win-x64/native/.

linux-dir:
	@mkdir -p runtimes/linux-arm64/native
	@mkdir -p runtimes/linux-arm/native
	@mkdir -p runtimes/linux-x64/native
	@cp ./target/arm-unknown-linux-gnueabi/release/librust_verkle.so ./runtimes/linux-arm/native/.
	@cp ./target/aarch64-unknown-linux-gnu/release/librust_verkle.so ./runtimes/linux-arm64/native/.
	@cp ./target/x86_64-unknown-linux-gnu/release/librust_verkle.so ./runtimes/linux-x64/native/.

clean:
#	rm -rf target
#	rm -rf build
#	rm -rf Cargo.lock
#	rm -rf osxcross
#	rm -rf runtimes