include ../target.mk

vpath %.c src:$(TOOLS):$(TOOLS)/aes_128
vpath %.o $(TMP)
vpath %.d $(TMP)

AES_VAL_SRC = aes_128_key_schedule.c \
			  aes_128_mix_columns.c  \
			  aes_128_s_box.c  \
			  aes_128_shift_rows.c  \
			  aes_128_validation.c \
			  aes_128.c  \
			  xor.c  \
			  pkcs7.c  \
			  b64.c

TMP_AES_VAL_OBJS = $(AES_VAL_SRC:.c=.o)
AES_VAL_OBJS = $(addprefix $(TMP)/, $(TMP_AES_VAL_OBJS))

OBJS := b64.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d)  


all : build_dir build solve 

.PHONY: libaes_128
libaes_128:
	$(MAKE) -C $(TOOLS) aes_128

build: build_dir $(OBJS) libaes_128
	$(CC) $(CFLAGS) -static -L$(TOOLS_LIB) $(OBJS) -o $(TARGET) -laes_128

.PHONY: validate
validate: $(AES_VAL_OBJS)
	gcc -g -Wall $(AES_VAL_OBJS) -o $(BIN)/aes_val
	$(BIN)/aes_val


.PHONY: solve
solve: build
	$(TARGET) < input.txt | tee result.txt
	@$(ECHO_NE)
	
# count the number of different lines :
	diff -U 0 result.txt solution.txt | grep ^@ | wc -l 