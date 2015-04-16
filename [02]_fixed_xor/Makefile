include ../global.mk

vpath %.o $(TMP)
vpath %.d $(TMP)


all: solve compile build_dir


OBJS := main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  


compile: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) 

.PHONY : solve
solve: compile
	$(TARGET) input1 input2 | tee result1
	@echo -ne "\n"
# count the number of different lines :
	diff -U 0 result1 solution1 | grep ^@ | wc -l 


