include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/mini-gmp
vpath %.o $(TMP)

OBJS := mini-gmp.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all: build_dir compile solve

mt_generate:
	$(MAKE) -C $(TOOLS)/ mt19937

compile: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB)  $(OBJS) -o $(TARGET) -lmt19937

.PHONY : solve
solve:	compile
	$(TARGET) | tee result.txt
	@echo -ne "\n"
	
	