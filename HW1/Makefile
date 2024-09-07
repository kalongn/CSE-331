# Compiler and flags
CXX := g++
CXXFLAGS := -Iinclude -Wall -Wextra -std=c++11

# Directories
SRCD := src
BLDD := build
BIND := bin

# Executable name
TARGET := vigcip

# Find all .cpp files in the src directory
SRCF := $(wildcard $(SRCD)/*.cpp)

# Convert .cpp files to corresponding .o files in the build directory
OBJF := $(patsubst $(SRCD)/%.cpp,$(BLDD)/%.o,$(SRCF))

# Default target
all: $(BIND)/$(TARGET)

# Linking
$(BIND)/$(TARGET): $(OBJF)
	@mkdir -p $(BIND)
	$(CXX) $(OBJF) -o $@

# Compiling
$(BLDD)/%.o: $(SRCD)/%.cpp
	@mkdir -p $(BLDD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up
clean:
	rm -rf $(BLDD) $(BIND)

# Phony targets
.PHONY: all clean
