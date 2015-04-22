include ../global.mk

vpath %.c aes_128
vpath %.o $(TMP)
vpath %.d $(TMP)

AES_128_OBJS := aes_128_key_schedule.o \
			    aes_128_mix_columns.o  \
			    aes_128_s_box.o  \
			    aes_128_shift_rows.o  \
			    pkcs7.o \
			    xor.o \
			    aes_128.o  
AES_128_OBJS := $(addprefix $(TMP)/, $(AES_128_OBJS))

SRC = $(wildcard *.c)
OBJ = $(addprefix $(TMP)/, $(SRC:.c=.o))
DEP = $(OBJ:.o=.d)  

ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif

tools: build_dir pkcs7 b64 mt19937 aes_128


$(TMP)/%.o : %.c
	$(CC) -I$(TOOLS) -c $< $(CFLAGS) -o $@


pkcs7: build_dir $(TMP)/pkcs7.o
	$(CC) $(CFLAGS) -DPKCS7_TOOL $@.c -o $(TOOL_TARGET)

b64: build_dir $(TMP)/b64.o
	$(CC) $(CFLAGS) -DB64_TOOL $@.c -o $(TOOL_TARGET)

aes_128: build_dir $(AES_128_OBJS)	
	ar rcs -o $(LIB)/libaes_128.a $(AES_128_OBJS)

mt19937: build_dir $(TMP)/mt19937.o
	ar rcs  -o $(LIB)/libmt19937.a $(TMP)/mt19937.o

