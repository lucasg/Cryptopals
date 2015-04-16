include ../global.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)
vpath %.d $(TMP)

ifeq ($(OS), Windows_NT)
	LDLIBS+=-lws2_32
endif

OBJS := sha1.o sha1_utils.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 


all : build_dir compile solve 


compile: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDLIBS)


.PHONY : solve
solve: compile
	$(TARGET)
