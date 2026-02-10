CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -g
BUILD_DIR = ./build
OBJ_DIR = $(BUILD_DIR)/.deps

client: $(OBJ_DIR)/client.o $(OBJ_DIR)/messages.o
	$(CC) $(CFLAGS) $(OBJ_DIR)/client.o $(OBJ_DIR)/messages.o -o $(BUILD_DIR)/client

$(OBJ_DIR)/client.o: client.cpp | $(OBJ_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/messages.o: synerp_messages.cpp | $(OBJ_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean
