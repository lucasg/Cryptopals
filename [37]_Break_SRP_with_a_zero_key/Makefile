include ../target.mk

vpath %.c $(TOOLS):$(TOOLS)/mini-gmp
vpath %.o $(TMP)

OBJS := mini-gmp.o hex.o sha256.o srp_utils.o client.o server.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

# CFLAGS+=-D_DEBUG_SRP

all: build_dir build solve

mt_generate:
	$(MAKE) -C $(TOOLS)/ mt19937

build: build_dir $(OBJS) mt_generate
	$(CC) $(CFLAGS) -static -L$(TOOLS_LIB)  $(OBJS) -o $(TARGET) -lmt19937

.PHONY : solve
solve:
	$(TARGET) "tests@example.com" "password123" | tee result.txt
	$(TARGET) "test@example.com" "test123" | tee result.txt
	$(TARGET) "test@example.com" "password123" | tee result.txt
	@$(ECHO_NE)
	
	