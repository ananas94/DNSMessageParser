EXECUTABLE_OUT="dnsrrparser"
LIBRARY_OUT="libdnsrrparser.a"

.PHONY: all
all: $(EXECUTABLE_OUT)  $(LIBRARY_OUT)

CC=gcc
CXX=g++

ifeq ($(DEBUG),true)
	CFLAGS += -fsanitize=address 
else
	CFLAGS += -O2
endif

BUILD_FOLDER:=build


INCLUDE_FOLDERS=-I./include
SOURCES_DIR=./src
OBJ_DIR=$(BUILD_FOLDER)/obj
DEP_DIR=$(BUILD_FOLDER)/dep

MAIN=ns_parser.cpp
MAIN_OBJ=$(OBJ_DIR)/$(MAIN:.cpp=.o)
C_SOURCES=$(wildcard $(SOURCES_DIR)/*.c)
CXX_SOURCES=$(wildcard $(SOURCES_DIR)/*.cpp)
CFLAGS=-g -Wall


DEP=$(addprefix $(DEP_DIR)/,$(notdir $(C_SOURCES:.c=.d)))
DEP+=$(addprefix $(DEP_DIR)/,$(notdir $(CXX_SOURCES:.cpp=.d)))

OBJ=$(addprefix $(OBJ_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
OBJ+=$(addprefix $(OBJ_DIR)/,$(notdir $(CXX_SOURCES:.cpp=.o)))


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

$(EXECUTABLE_OUT): $(LIBRARY_OUT) $(OBJ)
	$(CXX) $(CFLAGS) $(MAIN_OBJ) $(LIBRARY_OUT) $(LIBS) -o $(EXECUTABLE_OUT)

$(LIBRARY_OUT): $(filter-out $(MAIN_OBJ),$(OBJ))
	ar rvs $(LIBRARY_OUT) $^


clean:
	$(RM) $(EXECUTABLE_OUT)
	$(RM) $(LIBRARY_OUT)
	$(RM) $(BUILD_FOLDER)
