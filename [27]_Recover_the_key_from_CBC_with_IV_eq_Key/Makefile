include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)
vpath %.d $(TMP)


OBJS := target.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all : build_dir build solve 

.PHONY: libaes_128
libaes_128:
	$(MAKE) -C $(TOOLS)/ aes_128


build: build_dir $(OBJS) libaes_128
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB) $(OBJS) -o $(TARGET) -laes_128


.PHONY : solve
solve: build
	$(TARGET)
