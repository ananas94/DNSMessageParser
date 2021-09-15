EXECUTABLE="dnsrrparser"
LIBRARY="libdnsrrparser.a"
TESTS="dnsrrparser_test"

ifeq ($(DEBUG),true)
	CFLAGS += -fsanitize=address 
	SUFFIX = _dbg
else
	CFLAGS += -O2
endif

BUILD_FOLDER:=build${SUFFIX}/

EXECUTABLE_OUT="dnsrrparser${SUFFIX}"
LIBRARY_OUT="${BUILD_FOLDER}libdnsrrparser${SUFFIX}.a"
TESTS_OUT="dnsrrparser_test${SUFFIX}"

.PHONY: all
all: $(EXECUTABLE_OUT)  $(LIBRARY_OUT)

CC=gcc
CXX=g++


INCLUDE_FOLDERS=-I./include
SOURCES_DIR=./src
OBJ_DIR=$(BUILD_FOLDER)/obj
DEP_DIR=$(BUILD_FOLDER)/dep
TESTS_DIR=./tests

MAIN=ns_parser.cpp
MAIN_OBJ=$(OBJ_DIR)/$(MAIN:.cpp=.o)
C_SOURCES=$(wildcard $(SOURCES_DIR)/*.c)
CXX_SOURCES=$(wildcard $(SOURCES_DIR)/*.cpp)
CFLAGS+=-g -Wall


TESTS=$(wildcard $(TESTS_DIR)/*.cpp)

DEP=$(addprefix $(DEP_DIR)/,$(notdir $(C_SOURCES:.c=.d)))
DEP+=$(addprefix $(DEP_DIR)/,$(notdir $(CXX_SOURCES:.cpp=.d)))
DEP+=$(addprefix $(DEP_DIR)/,$(notdir $(TESTS:.cpp=.d)))

OBJ=$(addprefix $(OBJ_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
OBJ+=$(addprefix $(OBJ_DIR)/,$(notdir $(CXX_SOURCES:.cpp=.o)))
TESTS_OBJ=$(addprefix $(OBJ_DIR)/,$(notdir $(TESTS:.cpp=.o)))

TESTS_FLAGS=-I./gtest/include 
TESTS_LIBS=./gtest/lib/libgtest_main.a ./gtest/lib/libgtest.a -pthread

LIBS=

RM=rm -fr

$(OBJ_DIR):
	mkdir -p $@

$(DEP_DIR):
	mkdir -p $@

$(DEP_DIR)/%.d : $(SOURCES_DIR)/%.c  Makefile | $(DEP_DIR)
	$(CC) $(INCLUDE_FOLDERS) -MM -MT $(addprefix $(OBJ_DIR)/,$(notdir $(<:.c=.o)))  -c $< -o $@

$(DEP_DIR)/%.d : $(SOURCES_DIR)/%.cpp  Makefile | $(DEP_DIR)
	$(CXX) $(INCLUDE_FOLDERS) -MM -MT $(addprefix $(OBJ_DIR)/,$(notdir $(<:.cpp=.o)))  -c $< -o $@

-include $(DEP)

$(OBJ_DIR)/%.o : $(SOURCES_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_FOLDERS) -c $< -o $@

$(OBJ_DIR)/%.o : $(SOURCES_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CFLAGS) $(INCLUDE_FOLDERS) -c $< -o $@

$(OBJ_DIR)/%.o : $(TESTS_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CFLAGS) $(TESTS_FLAGS) $(INCLUDE_FOLDERS) -c $< -o $@

$(EXECUTABLE_OUT): $(LIBRARY_OUT) $(OBJ)
	$(CXX) $(CFLAGS) $(MAIN_OBJ) $(LIBRARY_OUT) $(LIBS) -o $@

$(LIBRARY_OUT): $(filter-out $(MAIN_OBJ),$(OBJ))
	ar rvs $(LIBRARY_OUT) $^

$(TESTS_OUT): $(LIBRARY_OUT) $(TESTS_OBJ)
	$(CXX) $(CFLAGS) $(TESTS_FLAGS) $(TESTS_LIBS) $(LIBRARY_OUT) $(TESTS_OBJ) $(LIBRARY_OUT) -o $@


.PHONY: tests
library: ${LIBRARY_OUT}

.PHONY: tests
tests: $(TESTS_OUT)

.PHONY: clean
clean:
	$(RM) $(EXECUTABLE_OUT)
	$(RM) $(LIBRARY_OUT)
	$(RM) $(TESTS_OUT)
	$(RM) $(BUILD_FOLDER)

