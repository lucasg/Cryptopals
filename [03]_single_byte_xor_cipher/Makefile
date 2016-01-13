include ../target.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)
vpath %.d $(TMP)

all: solve build build_dir  

OBJS := ifreq.o xor.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))

DEP = $(OBJS:.o=.d)  


build: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) 


.PHONY : solve
solve: build
	$(TARGET) cipher
	

