include ../global.mk

all: pkcs7_generate solve 

pkcs7_generate:
	$(MAKE) -C $(TOOLS) pkcs7

.PHONY : solve
solve: pkcs7_generate
ifeq ($(OS), Windows_NT)
	$(TOOLS)//$(BIN)/pkcs7.exe -s < input | tee output
else
	$(TOOLS)//$(BIN)/pkcs7 -s < input | tee output
endif

	@echo "\n"

