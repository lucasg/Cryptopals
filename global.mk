
# Toolchain used 
CC=gcc
CFLAGS= -g -Wall -MD -MP
LDFLAGS=
LDLIBS=

# Python specifics
PYTHON_INC = "C:\Program Files (x86)\Python3.4\include"
PYTHON_LIBFD = "C:\Program Files (x86)\Python3.4\libs"
PYTHON_LIB = python34

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
else
	ARCH = linux
	PYTHON = python3
	PIP = pip3
	
	MAKE = make
	AWK = awk
#RM_R = find -mindepth 1 -delete
	RM_R = rm -f
	
	TARGET = $(BIN)/$(TARGET_NAME)
	TOOL_TARGET = $(BIN)/$@
endif

# Output folders
TOOLS := ../tools
TMP := tmp_$(ARCH)
LIB := lib
BIN := bin
BDIR := $(TMP) $(BIN) $(LIB)



# Static rules
$(TMP)/%.o : %.c
	$(CC) $(CFLAGS) -I$(TOOLS) -L$(TOOLS)/$(LIB) -c $<  -o $@





# create build directories if it doesn't exist
.PHONY : build_dir
build_dir: ${BDIR}
${BDIR}:
	@mkdir -p ${BDIR}


.IGNORE: clean
.PHONY: clean
clean:
	@$(RM_R) $(BIN)/*
	@$(RM_R) $(LIB)/*
	@$(RM_R) $(TMP)/*
