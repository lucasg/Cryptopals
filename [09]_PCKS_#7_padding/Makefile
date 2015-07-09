include ../global.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)


OBJS := b64.o hex.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  

all : build_dir compile solve 

compile: build_dir $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)  

.PHONY : solve
solve: compile
	$(TARGET) -l 20 "YELLOW SUBMARINE" | tee result1
	@$(ECHO_NE)
	
# count the number of different lines :
	diff -U 0 result1 solution1 | grep ^@ | wc -l 
