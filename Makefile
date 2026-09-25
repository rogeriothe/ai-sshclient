BIN := ai-sshclient
MUSL_TARGET := x86_64-unknown-linux-musl
DIST_DIR := dist
INSTALL_DIR := $(HOME)/.local/bin

.PHONY: build dist test fmt lint install clean check-musl-toolchain

build:
	cargo build --release

# Static musl binary: no glibc/OpenSSL dependency on the target machine, so it runs on
# any x86_64 Linux with the same kernel ABI regardless of distro/glibc version.
dist: check-musl-toolchain
	cargo build --release --target $(MUSL_TARGET)
	mkdir -p $(DIST_DIR)
	cp target/$(MUSL_TARGET)/release/$(BIN) $(DIST_DIR)/$(BIN)-x86_64-linux
	strip $(DIST_DIR)/$(BIN)-x86_64-linux
	@echo "built $(DIST_DIR)/$(BIN)-x86_64-linux"
	@file $(DIST_DIR)/$(BIN)-x86_64-linux

check-musl-toolchain:
	@rustup target list --installed 2>/dev/null | grep -q $(MUSL_TARGET) || { \
		echo "missing rustup target $(MUSL_TARGET); run: rustup target add $(MUSL_TARGET)"; exit 1; }
	@command -v musl-gcc >/dev/null 2>&1 || { \
		echo "missing musl-gcc; run: sudo apt install musl-tools"; exit 1; }

test:
	cargo test -- --test-threads=1

fmt:
	cargo fmt --check

lint:
	cargo clippy -- -D warnings

# Installs the binary for the current user and makes sure ~/.local/bin is on PATH for
# both bash and zsh (appends the export line to ~/.bashrc / ~/.zshrc only if missing).
install: build
	mkdir -p $(INSTALL_DIR)
	install -m 755 target/release/$(BIN) $(INSTALL_DIR)/$(BIN)
	@echo "installed $(INSTALL_DIR)/$(BIN)"
	@for rc in $(HOME)/.bashrc $(HOME)/.zshrc; do \
		if [ -f "$$rc" ] || [ "$$rc" = "$(HOME)/.bashrc" ]; then \
			touch "$$rc"; \
			if ! grep -qs 'ai-sshclient PATH' "$$rc"; then \
				printf '\n# ai-sshclient PATH\nexport PATH="$(INSTALL_DIR):$$PATH"\n' >> "$$rc"; \
				echo "added $(INSTALL_DIR) to PATH in $$rc"; \
			else \
				echo "$$rc already updated"; \
			fi; \
		fi; \
	done
	@case ":$$PATH:" in \
		*":$(INSTALL_DIR):"*) ;; \
		*) echo "restart your shell (or 'source ~/.bashrc' / 'source ~/.zshrc') to pick up PATH" ;; \
	esac

clean:
	cargo clean
	rm -rf $(DIST_DIR)
