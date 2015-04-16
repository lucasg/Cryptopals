include ../global.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)
vpath %.d $(TMP)


OBJS := b64.o xor.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  


all: solve

compile: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) 

.PHONY : solve
solve: compile
	$(TARGET) < input1 | tee result1
	@echo -ne "\n"
	
# count the number of different lines :
	diff -U 0 result1 solution1 | grep ^@ | wc -l 

