include ../global.mk

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
ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif


all : build_dir compile validate solve 

.PHONY: libaes_128
libaes_128:
	$(MAKE) -C ../tools/ aes_128

compile: build_dir $(OBJS) libaes_128
	$(CC) $(CFLAGS) -static -L$(TOOLS)/$(LIB) $(OBJS) -o $(TARGET) -laes_128

validate: $(AES_VAL_OBJS)
	gcc -g -Wall $(AES_VAL_OBJS) -o $(BIN)/aes_val
	$(BIN)/aes_val


.PHONY: solve
solve: compile
	$(TARGET) < input.txt |tee output.txt
	@echo -ne "\n"
	
# count the number of different lines :
	diff -U 0 data/solution.txt data/7sanslines.decrypted.txt | grep ^@ | wc -l 