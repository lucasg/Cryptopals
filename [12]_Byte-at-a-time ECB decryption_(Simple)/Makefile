include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)


OBJS := b64.o ifreq.o hamdist.o aes_detect_ecb_mode.o aes_detect_block_size.o target.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif

all : build_dir lib_aes compile solve 

lib_aes:
	$(MAKE) -C ../tools/ aes_128


compile: build_dir $(OBJS) lib_aes
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB) $(OBJS) -o $(TARGET) -laes_128


.PHONY : solve
solve: compile
	$(TARGET) | tee result.txt