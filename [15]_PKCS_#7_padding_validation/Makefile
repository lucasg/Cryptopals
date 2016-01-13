include ../target.mk

all: build solve 

build: build_dir
	$(MAKE) -C $(TOOLS) pkcs7

.PHONY : solve
solve: build
ifeq ($(OS), Windows_NT)
	$(TOOLS_BIN)/pkcs7.exe -s < input | tee result
else
	$(TOOLS_BIN)/pkcs7 -s < input | tee result
endif

	@echo "\n"

