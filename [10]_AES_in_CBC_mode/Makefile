include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128


OBJS := b64.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  

all : build_dir lib_aes compile solve 

lib_aes:
	$(MAKE) -C ../tools/ aes_128

compile: build_dir $(OBJS) lib_aes
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB) $(OBJS) -o $(TARGET) -laes_128

.PHONY: solve
solve: compile
	$(TARGET) < input.txt | tee result.txt
	@echo -ne "\n"