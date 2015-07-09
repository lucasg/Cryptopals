include ../global.mk

vpath %.c $(TOOLS):$(TOOLS)/mini-gmp
vpath %.o $(TMP)

OBJS := mini-gmp.o hex.o sha256.o srp_utils.o client.o server.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

# CFLAGS+=-D_DEBUG_SRP

all: build_dir compile solve

SHA256_TEST_TARGET:=$(BIN)/test_sha256
ifeq ($(OS), Windows_NT)
	SHA256_TEST_TARGET:=$(BIN)/test_sha256.exe
endif

sha256_test: build_dir $(TMP)/sha256_test.o $(TMP)/sha256.o
	$(CC) $(CFLAGS) $(TMP)/sha256.o $(TMP)/sha256_test.o -o $(SHA256_TEST_TARGET)

mt_generate:
	$(MAKE) -C $(TOOLS)/ mt19937

compile: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB)  $(OBJS) -o $(TARGET) -lmt19937

.PHONY : solve
solve:	sha256_test compile
	$(SHA256_TEST_TARGET)
	$(TARGET) "test@example.com" "test123" | tee result.txt
	$(TARGET) "tests@example.com" "password123" | tee result.txt
	$(TARGET) "test@example.com" "password123" | tee result.txt
	@$(ECHO_NE)
	
	