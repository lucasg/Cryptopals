include ../target.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)

DECODE_TARGET:=$(BIN)/main_decrypt
ifeq ($(OS), Windows_NT)
	DECODE_TARGET:=$(BIN)/main_decrypt.exe
endif
DECODE_TOOLS = $(TOOLS)/hamdist.c \
			   $(TOOLS)/xor.c 	  \
			   $(TOOLS)/b64.c

OBJS := hamdist.o xor.o b64.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  

all: build_dir decode build solve

.PHONY: decode
decode: build_dir main_decrypt.c 
	$(CC) $(CFLAGS) $(DECODE_TOOLS) main_decrypt.c -o $(DECODE_TARGET)

build: build_dir $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)


.PHONY: solve
solve: build decode
	$(TARGET) input1.txt | tee result_keys.txt
	@$(ECHO_NE)
	@echo "Decoding with the most probable key"
	$(DECODE_TARGET) encoded_fixed.txt "Terminator X: Bring the noise" | tee result.txt
	@$(ECHO_NE)
