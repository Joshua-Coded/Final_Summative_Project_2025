# Blockchain Medical Records System - Makefile
# Professional build system for production-ready healthcare solution

# Project Configuration
PROJECT_NAME = medical_blockchain
VERSION = 1.0.0
BUILD_DATE = $(shell date '+%Y-%m-%d %H:%M:%S')

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = tests
DOC_DIR = docs
DATA_DIR = data
CONFIG_DIR = config # This variable is used for copying config files, not directly for include paths

# Compiler and flags
CC = clang # Explicitly use clang, common on macOS. Or keep gcc if it maps to clang.

# Common CFLAGS for all builds
CFLAGS_COMMON = -std=c99 -Wall -Wextra -Wpedantic -Werror -Wno-unused-result
CFLAGS_SECURITY = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE

# Build-specific CFLAGS
CFLAGS_DEBUG = $(CFLAGS_COMMON) -g -O0 -DDEBUG
CFLAGS_RELEASE = $(CFLAGS_COMMON) -O3 -DNDEBUG -flto

# Include paths for all source files.
# By including -I$(SRC_DIR), all includes in C files should be relative to 'src/'.
# E.g., #include "core/blockchain.h", #include "config/config.h"
# IMPORTANT: Explicitly adding all subdirectories of SRC_DIR to the include path
# This ensures that headers like "utils/colors.h" are found correctly,
# even if included from a different subdirectory like "core/block.c".
CFLAGS_INCLUDE = -I$(SRC_DIR) \
                 -I$(SRC_DIR)/core \
                 -I$(SRC_DIR)/crypto \
                 -I$(SRC_DIR)/mining \
                 -I$(SRC_DIR)/security \
                 -I$(SRC_DIR)/medical \
                 -I$(SRC_DIR)/contracts \
                 -I$(SRC_DIR)/storage \
                 -I$(SRC_DIR)/network \
                 -I$(SRC_DIR)/utils \
                 -I$(SRC_DIR)/cli \
                 -I$(SRC_DIR)/config \
                 $(shell pkg-config --cflags libcrypto) $(shell pkg-config --cflags json-c)

# Libraries specific to the main application (release/debug builds)
LIBS_APP = $(shell pkg-config --libs libcrypto) -lm -lpthread $(shell pkg-config --libs json-c)

# Libraries specific to the test build
LIBS_TEST = -lcunit -L/usr/local/lib

# Linker flags for security hardening
LDFLAGS_SECURITY = -fPIE

# Source files organized by module
CORE_SOURCES = $(wildcard $(SRC_DIR)/core/*.c)
CRYPTO_SOURCES = $(wildcard $(SRC_DIR)/crypto/*.c)
MINING_SOURCES = $(wildcard $(SRC_DIR)/mining/*.c)
SECURITY_SOURCES = $(wildcard $(SRC_DIR)/security/*.c)
MEDICAL_SOURCES = $(wildcard $(SRC_DIR)/medical/*.c)
CONTRACTS_SOURCES = $(wildcard $(SRC_DIR)/contracts/*.c)
STORAGE_SOURCES = $(wildcard $(SRC_DIR)/storage/*.c)
NETWORK_SOURCES = $(wildcard $(SRC_DIR)/network/*.c)
UTILS_SOURCES = $(wildcard $(SRC_DIR)/utils/*.c) # This will now pick up colors.c
CLI_SOURCES = $(wildcard $(SRC_DIR)/cli/*.c)
CONFIG_SOURCES = $(wildcard $(SRC_DIR)/config/*.c)

MAIN_SOURCE = $(SRC_DIR)/main.c

ALL_SOURCES = $(CORE_SOURCES) $(CRYPTO_SOURCES) $(MINING_SOURCES) \
              $(SECURITY_SOURCES) $(MEDICAL_SOURCES) $(CONTRACTS_SOURCES) \
              $(STORAGE_SOURCES) $(NETWORK_SOURCES) $(UTILS_SOURCES) \
              $(CLI_SOURCES) $(CONFIG_SOURCES) $(MAIN_SOURCE)

# Object files
# These patterns handle creating objects in specific subdirectories under obj/
# They convert `src/dir/file.c` to `obj/dir/file.o`
CORE_OBJECTS = $(patsubst $(SRC_DIR)/core/%.c,$(OBJ_DIR)/core/%.o,$(CORE_SOURCES))
CRYPTO_OBJECTS = $(patsubst $(SRC_DIR)/crypto/%.c,$(OBJ_DIR)/crypto/%.o,$(CRYPTO_SOURCES))
MINING_OBJECTS = $(patsubst $(SRC_DIR)/mining/%.c,$(OBJ_DIR)/mining/%.o,$(MINING_SOURCES))
SECURITY_OBJECTS = $(patsubst $(SRC_DIR)/security/%.c,$(OBJ_DIR)/security/%.o,$(SECURITY_SOURCES))
MEDICAL_OBJECTS = $(patsubst $(SRC_DIR)/medical/%.c,$(OBJ_DIR)/medical/%.o,$(MEDICAL_SOURCES))
CONTRACTS_OBJECTS = $(patsubst $(SRC_DIR)/contracts/%.c,$(OBJ_DIR)/contracts/%.o,$(CONTRACTS_SOURCES))
STORAGE_OBJECTS = $(patsubst $(SRC_DIR)/storage/%.c,$(OBJ_DIR)/storage/%.o,$(STORAGE_SOURCES))
NETWORK_OBJECTS = $(patsubst $(SRC_DIR)/network/%.c,$(OBJ_DIR)/network/%.o,$(NETWORK_SOURCES))
UTILS_OBJECTS = $(patsubst $(SRC_DIR)/utils/%.c,$(OBJ_DIR)/utils/%.o,$(UTILS_SOURCES)) # This will now include obj/utils/colors.o
CLI_OBJECTS = $(patsubst $(SRC_DIR)/cli/%.c,$(OBJ_DIR)/cli/%.o,$(CLI_SOURCES))
CONFIG_OBJECTS = $(patsubst $(SRC_DIR)/config/%.c,$(OBJ_DIR)/config/%.o,$(CONFIG_SOURCES))

MAIN_OBJECT = $(patsubst $(SRC_DIR)/main.c,$(OBJ_DIR)/main.o,$(MAIN_SOURCE))

ALL_OBJECTS = $(CORE_OBJECTS) $(CRYPTO_OBJECTS) $(MINING_OBJECTS) \
              $(SECURITY_OBJECTS) $(MEDICAL_OBJECTS) $(CONTRACTS_OBJECTS) \
              $(STORAGE_OBJECTS) $(NETWORK_OBJECTS) $(UTILS_OBJECTS) \
              $(CLI_OBJECTS) $(CONFIG_OBJECTS) $(MAIN_OBJECT)

# Test files
TEST_SOURCES = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJECTS = $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/test/%.o,$(TEST_SOURCES))

# Target executables
TARGET = $(BIN_DIR)/$(PROJECT_NAME)
TEST_TARGET = $(BIN_DIR)/test_runner

# Default target
.PHONY: all
all: release

# Debug build
.PHONY: debug
debug: CFLAGS = $(CFLAGS_DEBUG) $(CFLAGS_SECURITY)
debug: LDFLAGS = $(LDFLAGS_SECURITY) $(LIBS_APP)
debug: clean $(TARGET)
	@echo "Debug build completed successfully"

# Release build
.PHONY: release
release: CFLAGS = $(CFLAGS_RELEASE) $(CFLAGS_SECURITY)
release: LDFLAGS = $(LDFLAGS_SECURITY) $(LIBS_APP)
release: clean $(TARGET)
	@echo "Release build completed successfully"
	@strip $(TARGET)

# Create directories
# Ensure all nested object directories exist before compilation
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)/{core,crypto,mining,security,medical,contracts,storage,network,utils,cli,config,test}

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Build main executable
$(TARGET): $(ALL_OBJECTS) | $(BIN_DIR)
	@echo "Linking $(TARGET)..."
	@$(CC) $(CFLAGS) $(ALL_OBJECTS) -o $@ $(LDFLAGS)
	@echo "Build completed successfully!"

# **CRITICAL FIX HERE:**
# This general rule compiles any .c file found in a subdirectory of SRC_DIR
# into a .o file in the corresponding subdirectory of OBJ_DIR.
# The `*` in the dependency will match the path relative to SRC_DIR (e.g., 'core/block')
# and the target will construct the full path (e.g., 'obj/core/block.o').
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) $(CFLAGS_INCLUDE) -c $< -o $@

# Build test executable
$(TEST_TARGET): $(TEST_OBJECTS) $(filter-out $(MAIN_OBJECT), $(ALL_OBJECTS)) | $(BIN_DIR)
	@echo "Linking test executable..."
	@$(CC) $(CFLAGS_DEBUG) $(CFLAGS_INCLUDE) $(TEST_OBJECTS) $(filter-out $(MAIN_OBJECT), $(ALL_OBJECTS)) -o $@ $(LDFLAGS_SECURITY) $(LIBS_TEST)

# Compile test files
# Test object files are placed under $(OBJ_DIR)/test/
$(OBJ_DIR)/test/%.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling test $<..."
	@$(CC) $(CFLAGS_DEBUG) $(CFLAGS_INCLUDE) -c $< -o $@

# Run tests
.PHONY: test
test: $(TEST_TARGET)
	@echo "Running unit tests..."
	@./$(TEST_TARGET)
	@echo "All tests completed!"

# Memory check with Valgrind
.PHONY: memcheck
memcheck: debug
	@echo "Running memory check..."
	@valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
		--track-origins=yes --verbose $(TARGET) --test

# Static analysis
.PHONY: analyze
analyze:
	@echo "Running static analysis..."
	@cppcheck --enable=all --std=c99 --platform=unix64 \
		--suppress=missingIncludeSystem --quiet $(SRC_DIR)/
	@echo "Static analysis completed!"

# Code formatting
.PHONY: format
format:
	@echo "Formatting code..."
	@find $(SRC_DIR) -name "*.c" -o -name "*.h" | xargs clang-format -i
	@find $(TEST_DIR) -name "*.c" -o -name "*.h" | xargs clang-format -i
	@echo "Code formatting completed!"

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@doxygen Doxyfile 2>/dev/null || echo "Doxygen not available, skipping documentation generation"

# Install system-wide
.PHONY: install
install: release
	@echo "Installing $(PROJECT_NAME)..."
	@sudo cp $(TARGET) /usr/local/bin/
	@sudo mkdir -p /etc/$(PROJECT_NAME)
	@sudo cp $(CONFIG_DIR)/*.conf /etc/$(PROJECT_NAME)/
	@echo "Installation completed!"

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(PROJECT_NAME)..."
	@sudo rm -f /usr/local/bin/$(PROJECT_NAME)
	@sudo rm -rf /etc/$(PROJECT_NAME)
	@echo "Uninstallation completed!"

# Create distribution package
.PHONY: dist
dist: release
	@echo "Creating distribution package..."
	@mkdir -p dist/$(PROJECT_NAME)-$(VERSION)
	@cp -r $(SRC_DIR) $(DOC_DIR) $(CONFIG_DIR) Makefile README.md dist/$(PROJECT_NAME)-$(VERSION)/
	@cp $(TARGET) dist/$(PROJECT_NAME)-$(VERSION)/
	@cd dist && tar -czf $(PROJECT_NAME)-$(VERSION).tar.gz $(PROJECT_NAME)-$(VERSION)/
	@echo "Distribution package created: dist/$(PROJECT_NAME)-$(VERSION).tar.gz"

# Performance benchmarking
.PHONY: benchmark
benchmark: release
	@echo "Running performance benchmarks..."
	@time $(TARGET) --benchmark
	@echo "Benchmark completed!"

# Security scan
.PHONY: security-scan
security-scan:
	@echo "Running security scan..."
	@flawfinder $(SRC_DIR)/ || echo "Flawfinder not available"
	@bandit -r $(SRC_DIR)/ || echo "Bandit not available"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR) dist/
	@find . -name "*.gcno" -o -name "*.gcda" -o -name "*.gcov" | xargs rm -f
	@echo "Clean completed!"

# Show help
.PHONY: help
help:
	@echo "Blockchain Medical Records System - Build System"
	@echo "================================================="
	@echo ""
	@echo "Available targets:"
	@echo "  all             - Build the main executable (default)"
	@echo "  debug           - Build with debug information"
	@echo "  release         - Build optimized release version"
	@echo "  test            - Build and run unit tests"
	@echo "  memcheck        - Run memory leak detection"
	@echo "  analyze         - Run static code analysis"
	@echo "  format          - Format code with clang-format"
	@echo "  docs            - Generate documentation"
	@echo "  install         - Install system-wide"
	@echo "  uninstall       - Remove system installation"
	@echo "  dist            - Create distribution package"
	@echo "  benchmark       - Run performance benchmarks"
	@echo "  security-scan   - Run security analysis"
	@echo "  clean           - Clean build artifacts"
	@echo "  help            - Show this help message"
	@echo ""
	@echo "Project: $(PROJECT_NAME) v$(VERSION)"
	@echo "Build Date: $(BUILD_DATE)"

# Show project status
.PHONY: status
status:
	@echo "Project Status"
	@echo "=============="
	@echo "Name: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Source files: $(words $(ALL_SOURCES))"
	@echo "Test files: $(words $(TEST_SOURCES))"
	@echo "Build date: $(BUILD_DATE)"
	@echo ""
	@echo "Source Lines of Code:"
	@find $(SRC_DIR) -name "*.c" -exec wc -l {} + | tail -1
	@echo ""
	@echo "Recent changes:"
	@git log --oneline -5 2>/dev/null || echo "Not a git repository"

# Dependency information
.PHONY: deps
deps:
	@echo "Build Dependencies"
	@echo "=================="
	@echo "Compiler: $(CC)"
	@echo "Standard: C99"
	@echo "Libraries: $(LIBS_APP) (for app) and $(LIBS_TEST) (for tests)"
	@echo ""
	@echo "Optional tools:"
	@echo "- valgrind (memory checking)"
	@echo "- cppcheck (static analysis)"
	@echo "- clang-format (code formatting)"
	@echo "- doxygen (documentation)"

# Make all phony targets explicit
.PHONY: all debug release test memcheck analyze format docs install uninstall dist benchmark security-scan clean help status deps