include ../global.mk

vpath %.o $(TMP)
vpath %.d $(TMP)


all: solve build build_dir


OBJS := main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  


build: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) 

.PHONY : solve
solve: build
	$(TARGET) input1 input2 | tee result1
	@$(ECHO_NE)
# count the number of different lines :
	diff -U 0 result1 solution1 | grep ^@ | wc -l 


