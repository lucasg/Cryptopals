include ../target.mk

vpath %.c $(TOOLS):$(TOOLS)/mini-gmp
vpath %.o $(TMP)

OBJS := hex.o mini-gmp.o  mpz_invmod.o mpz_nextprime.o mpz_crt.o main.o
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
	
	