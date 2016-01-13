include ../global.mk



# Target naming rule
# Extract the number in [] from the project's path :  "/path/[XX]_foo_bar_baz/" -> "XX"
TARGET_NAME = $(shell pwd | sed 's/.*\[\([0-9]*\)\].*/\1/')

# OS-dependant tools and files
ifeq ($(OS), Windows_NT)
	TARGET = $(BIN)/$(TARGET_NAME).exe
else
	TARGET = $(BIN)/$(TARGET_NAME)
endif

TMP := ../build/$(TARGET_NAME)/tmp/$(OS_TARGET)
LIB := ../build/$(TARGET_NAME)/lib/$(OS_TARGET)
BIN := ../build/$(TARGET_NAME)/bin/$(OS_TARGET)


# create build directories if it doesn't exist
.IGNORE: build_dir
.PHONY: build_dir
build_dir: 
	@mkdir -p $(TMP)
	@mkdir -p $(BIN)
	@mkdir -p $(LIB)


# clean build directories 
.IGNORE: clean
.PHONY: clean
clean:
	@$(RM_R) $(BIN)/*
	@$(RM_R) $(LIB)/*
	@$(RM_R) $(TMP)/*


# Static rules
$(TMP)/%.o : %.c
	$(CC) $(CFLAGS) -I$(TOOLS) -L$(TOOLS_LIB) -c $<  -o $@
