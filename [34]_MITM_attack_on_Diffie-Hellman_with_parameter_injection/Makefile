include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128:$(TOOLS)/mini-gmp
vpath %.o $(TMP)


OBJS := mini-gmp.o sha1.o bot.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all : build_dir lib_aes compile solve 

lib_aes:
	$(MAKE) -C $(TOOLS)/ aes_128

lib_mt:
	$(MAKE) -C $(TOOLS)/ mt19937

build: build_dir $(OBJS) lib_aes lib_mt
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB) $(OBJS) -o $(TARGET) -laes_128 -lmt19937

.PHONY: solve
solve: compile
	$(TARGET) | tee result
