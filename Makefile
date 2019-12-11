
CPPFLAGS ?= -I . -I lib

all: make_keys archiver verifier

archiver: lib/uECC.c lib/SHA256.cpp archiver.cpp

verifier: lib/uECC.c lib/SHA256.cpp verifier.cpp

make_keys: lib/uECC.c lib/SHA256.cpp make_keys.cpp

.PHONY: clean
clean:
	rm -f archiver make_keys verifier
