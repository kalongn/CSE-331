# Compiler and flags
CXX := g++
CXXFLAGS := -Iinclude -I/opt/homebrew/opt/openssl/include -Wall -Wextra -std=c++11 -O3

# Directories
SRCD := src
BLDD := build
BIND := bin

# Executable name
TARGET := pc

# Find all .cpp files in the src directory
SRCF := $(wildcard $(SRCD)/*.cpp)

# Convert .cpp files to corresponding .o files in the build directory
OBJF := $(patsubst $(SRCD)/%.cpp,$(BLDD)/%.o,$(SRCF))

# Default target
all: $(BIND)/$(TARGET)

# Linking
$(BIND)/$(TARGET): $(OBJF)
	@mkdir -p $(BIND)
	$(CXX) $(OBJF) -L/opt/homebrew/opt/openssl/lib -lcrypto -o $@

# Compiling
$(BLDD)/%.o: $(SRCD)/%.cpp
	@mkdir -p $(BLDD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up
clean:
	rm -rf $(BLDD) $(BIND)

# Phony targets
.PHONY: all clean
