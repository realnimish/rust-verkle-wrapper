mkdir runtimes
cd runtimes
mkdir -p linux-arm/native
mkdir -p linux-arm64/native
mkdir -p linux-x64/native
mkdir -p osx-arm64/native
mkdir -p osx-x64/native
mkdir -p win-x64/native
cd ..
cp ./target/arm-unknown-linux-gnueabi/release/librust_verkle.so ./runtimes/linux-arm/native/.
cp ./target/aarch64-unknown-linux-gnu/release/librust_verkle.so ./runtimes/linux-arm64/native/.
cp ./target/x86_64-unknown-linux-gnu/release/librust_verkle.so ./runtimes/linux-x64/native/.
cp ./target/x86_64-apple-darwin/release/librust_verkle.dylib ./runtimes/osx-arm64/native/.
cp ./target/x86_64-apple-darwin/release/librust_verkle.dylib ./runtimes/osx-x64/native/.
cp ./target/x86_64-pc-windows-gnu/release/rust_verkle.dll ./runtimes/win-x64/native/.