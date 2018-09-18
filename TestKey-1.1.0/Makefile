
CPP      = g++ 
CC       = gcc 
OBJ      = main.o src/key.o src/pubkey.o src/uint256.o src/utilstrencodings.o src/arith_uint256.o secp256k1/src/secp256k1.o inc/crypto/ripemd160.o inc/crypto/sha256.o inc/crypto/sha512.o inc/crypto/hmac_sha512.o src/hash.o inc/script/standard.o inc/script/script.o inc/script/script_error.o src/keystore.o
LINKOBJ  = main.o src/key.o src/pubkey.o src/uint256.o src/utilstrencodings.o src/arith_uint256.o secp256k1/src/secp256k1.o inc/crypto/ripemd160.o inc/crypto/sha256.o inc/crypto/sha512.o inc/crypto/hmac_sha512.o src/hash.o inc/script/standard.o inc/script/script.o inc/script/script_error.o src/keystore.o
LIBS     = -L"/usr/lib" -L"/usr/local/lib"
INCS     = -I"./inc" -I"./secp256k1/include"
CXXINCS  = -I"./inc" -I"./secp256k1/include"
BIN      = testCKey
CXXFLAGS = $(CXXINCS) -std=gnu++0x
CFLAGS   = $(INCS) -std=gnu++0x
RM       = rm -f

.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CPP) $(LINKOBJ) -o $(BIN) $(LIBS)

main.o: main.cpp
	$(CPP) -c main.cpp -o main.o $(CXXFLAGS)

src/key.o: src/key.cpp
	$(CPP) -c src/key.cpp -o src/key.o $(CXXFLAGS)

src/pubkey.o: src/pubkey.cpp
	$(CPP) -c src/pubkey.cpp -o src/pubkey.o $(CXXFLAGS)

src/uint256.o: src/uint256.cpp
	$(CPP) -c src/uint256.cpp -o src/uint256.o $(CXXFLAGS)

src/utilstrencodings.o: src/utilstrencodings.cpp
	$(CPP) -c src/utilstrencodings.cpp -o src/utilstrencodings.o $(CXXFLAGS)

src/arith_uint256.o: src/arith_uint256.cpp
	$(CPP) -c src/arith_uint256.cpp -o src/arith_uint256.o $(CXXFLAGS)

secp256k1/src/secp256k1.o: secp256k1/src/secp256k1.c
	$(CPP) -c secp256k1/src/secp256k1.c -o secp256k1/src/secp256k1.o $(CXXFLAGS)

inc/crypto/ripemd160.o: inc/crypto/ripemd160.cpp
	$(CPP) -c inc/crypto/ripemd160.cpp -o inc/crypto/ripemd160.o $(CXXFLAGS)

inc/crypto/sha256.o: inc/crypto/sha256.cpp
	$(CPP) -c inc/crypto/sha256.cpp -o inc/crypto/sha256.o $(CXXFLAGS)

inc/crypto/sha512.o: inc/crypto/sha512.cpp
	$(CPP) -c inc/crypto/sha512.cpp -o inc/crypto/sha512.o $(CXXFLAGS)

inc/crypto/hmac_sha512.o: inc/crypto/hmac_sha512.cpp
	$(CPP) -c inc/crypto/hmac_sha512.cpp -o inc/crypto/hmac_sha512.o $(CXXFLAGS)

src/hash.o: src/hash.cpp
	$(CPP) -c src/hash.cpp -o src/hash.o $(CXXFLAGS)

inc/script/standard.o: inc/script/standard.cpp
	$(CPP) -c inc/script/standard.cpp -o inc/script/standard.o $(CXXFLAGS)

inc/script/script.o: inc/script/script.cpp
	$(CPP) -c inc/script/script.cpp -o inc/script/script.o $(CXXFLAGS)

inc/script/script_error.o: inc/script/script_error.cpp
	$(CPP) -c inc/script/script_error.cpp -o inc/script/script_error.o $(CXXFLAGS)

src/keystore.o: src/keystore.cpp
	$(CPP) -c src/keystore.cpp -o src/keystore.o $(CXXFLAGS)

