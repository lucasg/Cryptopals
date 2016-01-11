include ../global.mk

vpath %.o $(TMP)

OBJS := main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif

all: build_dir mt_generate compile solve

mt_generate:
	$(MAKE) -C $(TOOLS)/ mt19937


build: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB)  $(OBJS) -o $(TARGET) -lmt19937

.PHONY : solve
solve: compile 
	$(TARGET) | tee result.txt
	@$(ECHO_NE)
	
	