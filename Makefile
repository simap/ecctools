
CPPFLAGS ?= -I . -I lib

all: signer make_keys
signer: lib/uECC.c lib/SHA256.cpp signer.cpp

make_keys: lib/uECC.c lib/SHA256.cpp make_keys.cpp

