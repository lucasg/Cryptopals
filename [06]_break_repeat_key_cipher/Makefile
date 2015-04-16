TARGET=./6.exe

TOOLS=../tools/hamdist.c\
	  ../tools/ifreq.c\
	  ../tools/xor.c\
	  ../tools/b64.c 

all: decode break solve

.PHONY: decode
decode: main_decrypt.c 
	gcc -g -Wall $(TOOLS) main_decrypt.c -o ./$@

break:
	gcc -g -Wall $(TOOLS) main.c -o $(TARGET)


.PHONY: solve
solve: break
	$(TARGET) encoded_fixed.txt | tee probable_keys.txt
	@echo ""
	@echo "Decoding with the most probable key"
	./decode.exe encoded_fixed.txt "Terminator X: Bring the noise"

.PHONY: clean
clean:
	rm -rf $(TARGET)
	rm -rf ./decode