include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)

OBJS := hex.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif

all : build_dir aes_generate compile solve 

lib_aes:
	$(MAKE) -C ../tools/ aes_128

compile: build_dir $(OBJS) lib_aes
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB) $(OBJS) -o $(TARGET) -laes_128

.PHONY: solve
solve: compile
	$(TARGET) | tee output.txt