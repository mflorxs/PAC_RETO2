CXX      = g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++17
LDFLAGS  = -lssl -lcrypto -lpthread

BIN_DIR = bin

all: $(BIN_DIR)/emisor $(BIN_DIR)/detector

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/emisor: src/emisor.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

$(BIN_DIR)/detector: src/detector.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
