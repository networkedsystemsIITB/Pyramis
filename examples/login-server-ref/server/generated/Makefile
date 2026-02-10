CC = g++
CFLAGS = -std=c++17 -Wall -Wextra -g
LDFLAGS = -lsctp -lpthread
BUILD_DIR = ./build
DEPS_DIR = $(BUILD_DIR)/.deps
UTILITY_LIBRARY = ../../utility_library
LOG_LIB_DIR = $(UTILITY_LIBRARY)/platform/src

server: $(DEPS_DIR)/server_linking.o $(DEPS_DIR)/platform.o $(DEPS_DIR)/udf.o $(DEPS_DIR)/logging.o
	@$(CC) $(CFLAGS) $(DEPS_DIR)/server_linking.o $(DEPS_DIR)/platform.o $(DEPS_DIR)/udf.o $(DEPS_DIR)/logging.o -o $(BUILD_DIR)/server $(LDFLAGS)

$(DEPS_DIR)/server_linking.o: server_linking.cpp | $(DEPS_DIR)
	@$(CC) $(CFLAGS) -c server_linking.cpp -o $(DEPS_DIR)/server_linking.o

$(DEPS_DIR)/platform.o: synerp_platform.cpp | $(DEPS_DIR)
	@$(CC) $(CFLAGS) -c synerp_platform.cpp -o $(DEPS_DIR)/platform.o

$(DEPS_DIR)/udf.o: ../udf.cpp | $(DEPS_DIR)
	$(CC) $(CFLAGS) -c ../udf.cpp -o $(DEPS_DIR)/udf.o

$(DEPS_DIR)/logging.o: $(LOG_LIB_DIR)/logging.cpp | $(DEPS_DIR)
	$(CC) $(CFLAGS) -c $(LOG_LIB_DIR)/logging.cpp -o $(DEPS_DIR)/logging.o

$(DEPS_DIR):
	mkdir -p $(DEPS_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean
