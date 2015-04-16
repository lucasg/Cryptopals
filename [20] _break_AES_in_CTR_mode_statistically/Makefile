include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)


OBJS := b64.o ifreq.o generate.o analyze.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))

all : build_dir aes_generate compile solve 

aes_generate:
	$(MAKE) -C ../tools/ aes_128


compile: build_dir $(OBJS) aes_generate
	$(CC) $(CFLAGS) -static -L"../tools/lib/" $(OBJS) -o $(TARGET) -laes_128



.PHONY : solve
solve: compile
	rm -f result.txt
	mkdir -p ctexts
	
	$(TARGET) | tee result.txt
	@echo -ne "\n"
	
	