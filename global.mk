# 0x86 / 0x64_86 discrimination
ARCH := $(shell uname --machine)

# Toolchain used 
CC = gcc
CFLAGS = -g -Wall -MD -MP -pedantic #-ansi
LDFLAGS =
LDLIBS =

# OS-dependant tools and files
ifeq ($(OS), Windows_NT)
	OS_TARGET = win_$(ARCH)
	PYTHON = python
	PIP = pip
	
	MAKE = mingw32-make
	AWK = gawk
	RM_R = rm -f 

	ECHO_NE = echo -ne "\n"
else
	OS_TARGET = lin_$(ARCH)
	PYTHON = python3
	PIP = pip3
	
	MAKE = make
	AWK = awk
	RM_R = rm -f
	

	ECHO_NE = echo "\n"
endif


# Output folders for tools
TOOLS := ../tools
TOOLS_TMP := ../build/tools/tmp/$(OS_TARGET)
TOOLS_LIB := ../build/tools/lib/$(OS_TARGET)
TOOLS_BIN := ../build/tools/bin/$(OS_TARGET)


# Include dependencies 
ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif



# Action to do when calling "make" without args
.PHONY: no_target
no_target: build
