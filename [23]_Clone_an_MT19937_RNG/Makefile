include ../global.mk

vpath %.o $(TMP)

OBJS := main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif

all: build_dir mt_generate compile solve

mt_generate:
	$(MAKE) -C ../tools/ mt19937


compile: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB)  $(OBJS) -o $(TARGET) -lmt19937

.PHONY : solve
solve: compile 
	$(TARGET) | tee result.txt
	@echo -ne "\n"
	
	