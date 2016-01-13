include ../target.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)
vpath %.d $(TMP)

ifeq ($(OS), Windows_NT)
	LDLIBS+=-lws2_32
endif

OBJS := md4.o md4_utils.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all : build_dir build solve 


build: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDLIBS)


.PHONY : solve
solve: build
	$(TARGET)
