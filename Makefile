# Makefile wrapper for K-Watch (satisfies R6.7)

BUILD_DIR ?= build

all:
	cmake -B $(BUILD_DIR) && cmake --build $(BUILD_DIR)

# Regenerates asciinema casts and SVGs (R6.7)
demo: all
	@echo "[*] Regenerating demo media..."
	./docs/media/record.sh

tests: all
	./$(BUILD_DIR)/kwatch_tests

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all demo tests clean
