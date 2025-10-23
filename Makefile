CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wno-unused-parameter -O0 -g -I.
LDFLAGS = -lcapstone -lasmjit
# Updated sources after moving emitter functionality into codegen.cpp
SOURCES = main.cpp parser.cpp analyzer.cpp ast_printer.cpp ast.cpp codegen.cpp codegen_array.cpp library.cpp goroutine.cpp gc.cpp asm_library.cpp data_structures/safe_unordered_list.cpp
TARGET = technoscript
TEST_TARGET = test_safe_unordered_list
TEST_SOURCES = tests/test_safe_unordered_list.cpp data_structures/safe_unordered_list.cpp

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TEST_TARGET) $(TEST_SOURCES)

clean:
	rm -f $(TARGET) $(TEST_TARGET)

.PHONY: clean
