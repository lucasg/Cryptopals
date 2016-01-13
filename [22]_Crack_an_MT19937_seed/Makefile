include ../target.mk

vpath %.o $(TMP)

OBJS := main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))

ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif


all: build_dir mt_generate build solve

mt_generate:
	$(MAKE) -C ../tools/ mt19937

build: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS_LIB)  $(OBJS) -o $(TARGET) -lmt19937


.PHONY : solve
solve: build
	$(TARGET) | tee result.txt
	@echo  "\n"
	
	