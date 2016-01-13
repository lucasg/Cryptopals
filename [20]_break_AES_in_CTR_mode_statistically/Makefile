include ../target.mk

vpath %.c $(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)


OBJS := b64.o ifreq.o generate.o analyze.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))

all : build_dir aes_generate build solve 

aes_generate:
	$(MAKE) -C ../tools/ aes_128


build: build_dir $(OBJS) aes_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS_LIB) $(OBJS) -o $(TARGET) -laes_128



.PHONY : solve
solve: build
	rm -f result.txt
	mkdir -p ctexts
	
	$(TARGET) | tee result.txt
	@$(ECHO_NE)
	
	