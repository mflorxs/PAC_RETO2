CXX      = g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++17
LDFLAGS  = -lssl -lcrypto -lpthread

all: emisor detector

emisor: src/emisor.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

detector: src/detector.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f emisor detector

.PHONY: all clean
