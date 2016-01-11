include ../global.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)
vpath %.d $(TMP)


OBJS := sha1.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all : build_dir compile solve 


build: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)


.PHONY : solve
solve: compile
	$(TARGET)
