CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wno-unused-parameter -O0 -g
LDFLAGS = -lcapstone -lasmjit
# Updated sources after moving emitter functionality into codegen.cpp
SOURCES = main.cpp parser.cpp analyzer.cpp ast_printer.cpp ast.cpp codegen.cpp library.cpp goroutine.cpp
TARGET = technoscript

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
