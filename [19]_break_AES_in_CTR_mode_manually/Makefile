include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)


OBJS := b64.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))

ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif


all: build_dir aes_generate compile solve 

aes_generate:
	$(MAKE) -C ../tools/ aes_128


compile: build_dir $(OBJS)
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB) $(OBJS) -o $(TARGET) -laes_128


.PHONY : solve
solve: compile
	rm -f result.txt
	mkdir -p ctexts
	$(TARGET)
	touch result.txt

	for i in $(shell find ctexts -type f); do find ctexts -type f | xargs $(PYTHON) matrix.py $$i  | tee -a result.txt  ; done

	@echo -ne "\n"
