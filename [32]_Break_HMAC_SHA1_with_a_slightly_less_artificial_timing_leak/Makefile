include ../global.mk

vpath %.c $(TOOLS)
vpath %.o $(TMP)
vpath %.d $(TMP)

ifeq ($(OS), Windows_NT)
	CFLAGS+= -DCURL_STATICLIB
	LDLIBS+= -lcurl -lrtmp -lwinmm  -lssh2 -lz -lidn -lssl -lcrypto -lwldap32 -lws2_32 -lgdi32 -lcrypt32
	LDFLAGS+= -L$(LIB) -L$(TOOLS)/$(LIB) -static
else
# On linux, usually libcurl is already installed, or easy to download (using the package manager).
# You have the choice of using it either statically or dynamically (shared lib).
#
# For the dynamic lib, uncomment the two following lines and comment the rest :
# LDLIBS += -lcurl
# LDFLAGS+= -L/usr/lib/x86_64-linux-gnu

	CFLAGS+= -DCURL_STATICLIB
	LDLIBS+=  -lcurl -lrtmp  -lz -lidn -lssl -lcrypto -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -llber -llber -lldap
	LDFLAGS+= -L/usr/lib/x86_64-linux-gnu # Don't forget to modify this path : it need to point to the folder where the lib is installed
endif

OBJS := hex.o timer.o main.o
OBJS := $(addprefix $(TMP)/, $(OBJS))
DEP = $(OBJS:.o=.d) 

all : build_dir compile solve 


# The webserver use Python's bottle framework.
bottle:
	$(PIP) install bottle

# The hmac generation used by the webserver is done
# using the sha1.c implementation. There is a binding needed to
# glue the C code with the python script
libsha1_hmac:
ifeq ($(OS), Windows_NT)
	$(PYTHON) setup.py build --compiler=mingw32
else
	$(PYTHON) setup.py install --home=$(CURDIR)
endif

.PHONY: webserver
webserver:  libsha1_hmac
ifeq ($(OS), Windows_NT)
	mv $(shell find build -type f -name "sha1*.pyd") $(LIB)
else
	mv $(shell find $(LIB)/python -type f -name "sha1*.so") $(LIB)
endif
	$(PYTHON) hmac_server.py

compile: build_dir $(OBJS) 
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LDLIBS)


.PHONY : solve
solve: compile
	$(TARGET)

