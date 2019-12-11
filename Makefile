
CPPFLAGS ?= -I . -I lib

all: signer make_keys verifier

signer: lib/uECC.c lib/SHA256.cpp signer.cpp

verifier: lib/uECC.c lib/SHA256.cpp verifier.cpp

make_keys: lib/uECC.c lib/SHA256.cpp make_keys.cpp

.PHONY: clean
clean:
	rm -f signer make_keys
