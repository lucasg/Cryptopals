include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)


OBJS := target.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all : build_dir lib_aes build solve 


lib_aes:
	$(MAKE) -C $(TOOLS)/ aes_128


build: build_dir $(OBJS) lib_aes
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB)	 $(OBJS) -o $(TARGET) -laes_128

.PHONY: solve
solve: build
	$(TARGET) | tee result
