# Makefile wrapper for K-Watch

BUILD_DIR ?= build

all:
	cmake -B $(BUILD_DIR) && cmake --build $(BUILD_DIR)

# Optional: regenerate legacy asciinema demo media.
demo: all
	@echo "[*] Regenerating demo media..."
	./docs/media/record.sh

tests: all
	./$(BUILD_DIR)/kwatch_tests

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all demo tests clean
