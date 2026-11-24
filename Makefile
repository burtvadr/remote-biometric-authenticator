# Remote Biometric Authenticator — top-level developer tasks.
#
# `make help` lists everything. The individual toolchains live in their own
# sub-projects; this file only wires them together.

SHELL := /bin/bash
.DEFAULT_GOAL := help

CARGO ?= cargo
GRADLE ?= $(HOME)/.local/tc/gradle-8.10.2/bin/gradle
KTORLIN_HOME ?= $(HOME)/.local/tc/kotlin/kotlinc
JDK_HOME ?= $(HOME)/.local/tc/jdk21
ANDROID_HOME ?= $(HOME)/android-sdk
VECTORS := protocol/test-vectors

.PHONY: help
help: ## Show this help
	@echo "Remote Biometric Authenticator"
	@echo
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Quick start:"
	@echo "  make vectors        regenerate the cross-language protocol vectors"
	@echo "  make test           Rust unit, security and vector tests"
	@echo "  make e2e            full daemon + simulator smoke test"
	@echo "  make verify         everything that does not need an Android device"
	@echo "  make android-all    lint, test and build the Android app"

# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

.PHONY: build
build: ## Build every Rust component
	cd linux && $(CARGO) build

.PHONY: release
release: ## Build optimised Rust components
	cd linux && $(CARGO) build --release

.PHONY: test
test: ## Run all Rust tests (protocol, daemon, security, vectors)
	cd linux && $(CARGO) test
	$(CARGO) test --manifest-path crates/rba-enrollment/Cargo.toml

.PHONY: test-protocol
test-protocol: ## Run only the protocol crate tests
	cd linux && $(CARGO) test -p rba-protocol

.PHONY: test-security
test-security: ## Run only the security test suite
	cd linux && $(CARGO) test -p rbad --test security

.PHONY: lint
lint: ## rustfmt and clippy across the workspace
	cd linux && $(CARGO) fmt --all -- --check
	cd linux && $(CARGO) clippy --all-targets -- -D warnings

.PHONY: fmt
fmt: ## Apply rustfmt
	cd linux && $(CARGO) fmt --all

# ---------------------------------------------------------------------------
# Cross-language protocol vectors
# ---------------------------------------------------------------------------

.PHONY: vectors
vectors: ## Regenerate protocol/test-vectors from the Rust implementation
	cd linux && $(CARGO) run -q -p rba-protocol --bin vecgen -- ../$(VECTORS)
	@echo "wrote $(VECTORS)"

.PHONY: vectors-kt
vectors-kt: ## Run the Kotlin implementation against the shared vectors
	@if [ -x "$(JDK_HOME)/bin/java" ] && [ -x "$(KTORLIN_HOME)/bin/kotlinc" ]; then \
		export JAVA_HOME="$(JDK_HOME)"; export PATH="$(JDK_HOME)/bin:$(PATH)"; \
		echo "==> compiling the Kotlin protocol implementation"; \
		mkdir -p build/kotlin-protocol; \
		$(KTORLIN_HOME)/bin/kotlinc -jvm-target 21 -d build/kotlin-protocol \
			android/protocol/src/main/kotlin/io/github/burtvadr/rba/protocol/*.kt \
			android/protocol/src/test/kotlin/io/github/burtvadr/rba/protocol/VectorRunner.kt \
			android/protocol/src/test/kotlin/io/github/burtvadr/rba/protocol/Main.kt || exit 1; \
		echo "==> running the conformance vectors"; \
		$(JDK_HOME)/bin/java -cp "build/kotlin-protocol:$(KTORLIN_HOME)/lib/kotlin-stdlib.jar" \
			io.github.burtvadr.rba.protocol.MainKt $(VECTORS); \
	else \
		echo "skipping: need both a JDK (JDK_HOME=$(JDK_HOME)) and kotlinc (KTORLIN_HOME=$(KTORLIN_HOME))"; \
	fi

.PHONY: conformance
conformance: test-protocol vectors-kt ## Both implementations against the vectors

# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------

.PHONY: e2e
e2e: build ## Run the full daemon + simulator smoke test
	./tests/e2e-smoke.sh

.PHONY: pam-test
pam-test: build ## Load the real module into libpam and drive real authentication
	./tests/pam-integration.sh

.PHONY: sudo-test
sudo-test: build ## Insert into /etc/pam.d/sudo, test, then roll back (needs root)
	./tests/sudo-integration.sh

.PHONY: verify
verify: lint test vectors-kt e2e ## Everything verifiable without an Android device

.PHONY: polkit-test
polkit-test: build ## Register a real polkit agent and drive a real authorization (needs root)
	./tests/polkit-integration.sh

.PHONY: common-auth-test
common-auth-test: build ## One common-auth line: prove every password prompt uses the device
	./tests/common-auth-integration.sh

.PHONY: verify-pam
verify-pam: lint test vectors-kt e2e pam-test sudo-test ## Verify, including a live PAM and a real sudo
	@echo
	@echo "PAM and sudo exercised against a live libpam stack, a real rbad,"
	@echo "and a paired simulator. /etc/pam.d/sudo was restored from backup."

.PHONY: verify-all-auth
verify-all-auth: common-auth-test sudo-test ## Every password prompt on the system, then real sudo
	@echo
	@echo "One line in common-auth authenticated polkit-1 (the GNOME dialog), gdm-password"
	@echo "(screen unlock), sudo, login and su. Both files restored from backup."

.PHONY: verify-desktop
verify-desktop: polkit-test ## Verify the polkit agent against a live polkitd
	@echo
	@echo "A real polkitd was driven through a real authentication agent."

# ---------------------------------------------------------------------------
# Android
# ---------------------------------------------------------------------------

.PHONY: android-build
android-build: ## Assemble the debug APK
	cd android && JAVA_HOME="$(JDK_HOME)" ANDROID_HOME="$(ANDROID_HOME)" PATH="$(JDK_HOME)/bin:$$PATH" $(GRADLE) --no-daemon :app:assembleDebug

.PHONY: android-test
android-test: ## Run the Android unit tests
	cd android && JAVA_HOME="$(JDK_HOME)" ANDROID_HOME="$(ANDROID_HOME)" PATH="$(JDK_HOME)/bin:$$PATH" $(GRADLE) --no-daemon :app:testDebugUnitTest

.PHONY: android-lint
android-lint: ## Run Android lint
	cd android && JAVA_HOME="$(JDK_HOME)" ANDROID_HOME="$(ANDROID_HOME)" PATH="$(JDK_HOME)/bin:$$PATH" $(GRADLE) --no-daemon :app:lintDebug

.PHONY: kotlin-gradle-test
kotlin-gradle-test: ## Run the protocol conformance tests through Gradle
	cd android && JAVA_HOME="$(JDK_HOME)" ANDROID_HOME="$(ANDROID_HOME)" PATH="$(JDK_HOME)/bin:$$PATH" $(GRADLE) --no-daemon :protocol:test

.PHONY: android-all
android-all: android-lint kotlin-gradle-test android-test android-build ## Lint, test and build the app and protocol

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------

.PHONY: clean
clean: ## Remove build output
	rm -rf build linux/target android/app/build android/protocol/build android/.gradle
	rm -rf /tmp/rba-e2e

.PHONY: status
status: ## Show which toolchains are available
	@printf '%-22s %s\n' "cargo" "$$($(CARGO) --version 2>/dev/null || echo 'missing')"
	@printf '%-22s %s\n' "rustc" "$$(rustc --version 2>/dev/null || echo 'missing')"
	@printf '%-22s %s\n' "clippy" "$$($(CARGO) clippy --version 2>/dev/null | head -1 || echo 'missing')"
	@printf '%-22s %s\n' "java" "$$($(JDK_HOME)/bin/java -version 2>&1 | head -1 || echo missing)"
	@printf '%-22s %s\n' "kotlinc" "$$(export JAVA_HOME=$(JDK_HOME); export PATH=$(JDK_HOME)/bin:$$PATH; $(KTORLIN_HOME)/bin/kotlinc -version 2>&1 | head -1 || echo missing)"
	@printf '%-22s %s\n' "gradle" "$$(export JAVA_HOME=$(JDK_HOME); export PATH=$(JDK_HOME)/bin:$$PATH; $(GRADLE) --version 2>/dev/null | grep -m1 Gradle || echo missing)"
	@printf '%-22s %s\n' "android sdk" "$$([ -d "$(ANDROID_HOME)/platforms" ] && echo "$(ANDROID_HOME)" || echo missing)"