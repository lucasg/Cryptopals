include ../global.mk


# OS-dependant tools and files
ifeq ($(OS), Windows_NT)
	TOOL_TARGET = $(TOOLS_BIN)/$@.exe
	MAKE = mingw32-make
else
	TOOL_TARGET = $(TOOLS_BIN)/$@
	MAKE = make
endif

# create build directories if it doesn't exist
.IGNORE: build_tools_dir
.PHONY: build_tools_dir
build_tools_dir: 
	@mkdir -p $(TOOLS_TMP)
	@mkdir -p $(TOOLS_LIB)
	@mkdir -p $(TOOLS_BIN)

# clean build directories 
.IGNORE: clean
.PHONY: clean
clean:
	@$(RM_R) $(TOOLS_BIN)/*
	@$(RM_R) $(TOOLS_LIB)/*
	@$(RM_R) $(TOOLS_TMP)/*