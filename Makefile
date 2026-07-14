.PHONY: build test install deb rpm pkg docker clean bench fmt clippy all

all: build

build:
	cargo build --release

test:
	cargo test --workspace

install:
	cargo install --path backend --bin sentinelx-backend
	cargo install --path apps/cli --bin sentinelx-cli

deb:
	@command -v dpkg-buildpackage >/dev/null 2>&1 || { echo "Error: dpkg-dev not found"; exit 1; }
	cd packaging && dpkg-buildpackage -us -uc -b

rpm:
	@command -v rpmbuild >/dev/null 2>&1 || { echo "Error: rpmbuild not found"; exit 1; }
	rpmbuild -bb packaging/sentinelx.spec

pkg:
	@command -v makepkg >/dev/null 2>&1 || { echo "Error: makepkg not found (install pacman)"; exit 1; }
	cd packaging && makepkg -sf

docker:
	docker build -t sentinelx:1.0.0 -f Dockerfile .

clean:
	cargo clean

bench:
	cargo bench --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings
