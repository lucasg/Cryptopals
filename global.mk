# Toolchain used 
CC=gcc
CFLAGS= -g -Wall -MD -MP -pedantic #-ansi
LDFLAGS=
LDLIBS=

# Target naming rule
# Extract the number in [] from the project's path :  "/path/[XX]_foo_bar_baz/" -> "XX"
TARGET_NAME = $(shell pwd | sed 's/.*\[\([0-9]*\)\].*/\1/')


# OS-dependant tools and files
ifeq ($(OS), Windows_NT)
	ARCH = win
	PYTHON = python
	PIP = pip
	
	MAKE = mingw32-make
	AWK = gawk
	RM_R = rm -f 

	TARGET = $(BIN)/$(TARGET_NAME).exe
	TOOL_TARGET = $(BIN)/$@.exe

	ECHO_NE = echo -ne "\n"
else
	ARCH = linux_$(shell uname --machine)
	PYTHON = python3
	PIP = pip3
	
	MAKE = make
	AWK = awk
	RM_R = rm -f
	
	TARGET = $(BIN)/$(TARGET_NAME)
	TOOL_TARGET = $(BIN)/$@

	ECHO_NE = echo "\n"
endif


# Output folders
TOOLS := ../tools
TMP := tmp/$(ARCH)
LIB := lib/$(ARCH)
BIN := bin/$(ARCH)
BDIR := $(TMP) $(BIN) $(LIB)

# Include dependencies 
ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif

# Static rules
$(TMP)/%.o : %.c
	$(CC) $(CFLAGS) -I$(TOOLS) -L$(TOOLS)/$(LIB) -c $<  -o $@



# Action to do when calling "make" without args
.PHONY: no_target
no_target: build

# create build directories if it doesn't exist
.IGNORE: build_dir
.PHONY: build_dir
build_dir: 
	@mkdir -p $(TMP)
	@mkdir -p $(BIN)
	@mkdir -p $(LIB)
#${BDIR}:

# clean build directories 
.IGNORE: clean
.PHONY: clean
clean:
	@$(RM_R) $(BIN)/*
	@$(RM_R) $(LIB)/*
	@$(RM_R) $(TMP)/*
