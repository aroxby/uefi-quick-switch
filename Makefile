SRCS=$(wildcard *.cpp)
TARGET=uefi-quick-switch

CXXFLAGS=-std=c++20

.PHONY: all
all: $(TARGET)

$(TARGET): $(SRCS)
	g++ $(CXXFLAGS) $^ -o $@