include ../target.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)
vpath %.d $(TMP)


OBJS := b64.o xor.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  

.PHONY: all
all: solve

build: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) 

.PHONY : solve
solve: build
	$(TARGET) < input1 | tee result1
	@$(ECHO_NE)
	
# count the number of different lines :
	diff -U 0 result1 solution1 | grep ^@ | wc -l 
