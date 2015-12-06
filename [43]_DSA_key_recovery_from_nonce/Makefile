include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/mini-gmp
vpath %.o $(TMP)

OBJS := b64.o hex.o mini-gmp.o sha1.o mpz_invmod.o dsa.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all: build_dir compile solve

mt_generate:
	$(MAKE) -C $(TOOLS)/ mt19937

compile: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB)  $(OBJS) -o $(TARGET) -lmt19937

.PHONY : solve
solve:	compile
	$(TARGET) | tee result.txt
	@$(ECHO_NE)
	