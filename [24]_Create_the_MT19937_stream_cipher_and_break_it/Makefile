include ../target.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)

OBJS := xor.o target.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all: build_dir mt_generate build solve

mt_generate:
	$(MAKE) -C $(TOOLS)/ mt19937

build: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS_LIB)  $(OBJS) -o $(TARGET) -lmt19937

.PHONY : solve
solve:	build
	$(TARGET) | tee result.txt
	@$(ECHO_NE)
	
	