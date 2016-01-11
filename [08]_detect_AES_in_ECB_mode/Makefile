include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)

OBJS := hex.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  

all : build_dir lib_aes compile solve 

lib_aes:
	$(MAKE) -C $(TOOLS) aes_128

build: build_dir $(OBJS) lib_aes
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB) $(OBJS) -o $(TARGET) -laes_128

.PHONY: solve
solve: compile
	$(TARGET) | tee result.txt