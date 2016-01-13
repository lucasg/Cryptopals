include ../tools.mk

vpath %.c aes_128
vpath %.o $(TOOLS_TMP)
vpath %.d $(TOOLS_TMP)

AES_128_OBJS := aes_128_key_schedule.o \
			    aes_128_mix_columns.o  \
			    aes_128_s_box.o  \
			    aes_128_shift_rows.o  \
			    pkcs7.o \
			    xor.o \
			    aes_128.o  
AES_128_OBJS := $(addprefix $(TOOLS_TMP)/, $(AES_128_OBJS))

SRC = $(wildcard *.c)
OBJ = $(addprefix $(TOOLS_TMP)/, $(SRC:.c=.o))
DEP = $(OBJ:.o=.d)  



ifneq ($(MAKECMDGOALS),clean)
-include $(DEP)
endif

tools: build_tools_dir pkcs7 b64 mt19937 aes_128


$(TOOLS_TMP)/%.o : %.c	
	$(CC) -I. -c $< $(CFLAGS) -o $@


pkcs7: build_tools_dir $(TOOLS_TMP)/pkcs7.o
	$(CC) $(CFLAGS) -DPKCS7_TOOL $@.c -o $(TOOL_TARGET)

b64: build_tools_dir $(TOOLS_TMP)/b64.o
	$(CC) $(CFLAGS) -DB64_TOOL $@.c -o $(TOOL_TARGET)

aes_128: build_tools_dir $(AES_128_OBJS)	
	ar rcs -o $(TOOLS_LIB)/libaes_128.a $(AES_128_OBJS)

mt19937: build_tools_dir $(TOOLS_TMP)/mt19937.o
	ar rcs  -o $(TOOLS_LIB)/libmt19937.a $(TOOLS_TMP)/mt19937.o

