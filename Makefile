CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wno-unused-parameter -O0
# Updated sources after moving emitter functionality into codegen.cpp
SOURCES = main.cpp parser.cpp analyzer.cpp ast_printer.cpp codegen.cpp emitter.cpp library.cpp
TARGET = technoscript

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)

.PHONY: clean
