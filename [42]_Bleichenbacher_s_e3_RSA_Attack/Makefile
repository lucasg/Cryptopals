include ../target.mk

vpath %.c $(TOOLS):$(TOOLS)/mini-gmp
vpath %.o $(TMP)

OBJS := b64.o hex.o mini-gmp.o sha1.o sha256.o mpz_invmod.o mpz_nextprime.o rsa_utils.o pkcs1_v1.5.o client.o server.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all: build_dir build solve

mt_generate:
	$(MAKE) -C $(TOOLS)/ mt19937

build: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS_LIB)  $(OBJS) -o $(TARGET) -lmt19937

.PHONY : solve
solve:	build
	$(TARGET) | tee result.txt
	@$(ECHO_NE)
	