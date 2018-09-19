
CPP      = g++ 
CC       = gcc 
OBJ      = main.o src/key.o src/pubkey.o src/uint256.o src/utilstrencodings.o src/arith_uint256.o secp256k1/src/secp256k1.o inc/crypto/ripemd160.o inc/crypto/sha256.o inc/crypto/sha512.o inc/crypto/hmac_sha512.o src/hash.o inc/script/standard.o inc/script/script.o inc/script/script_error.o src/keystore.o inc/primitives/transaction.o inc/script/ismine.o inc/script/interpreter.o inc/crypto/sha1.o inc/script/sign.o inc/univalue/lib/univalue.o src/bech32.o inc/univalue/lib/univalue_get.o inc/univalue/lib/univalue_read.o inc/univalue/lib/univalue_write.o inc/support/cleanse.o inc/primitives/block.o src/netaddress.o src/protocol.o inc/consensus/merkle.o src/chainparams.o src/chainparamsbase.o src/base58.o
LINKOBJ  = main.o src/key.o src/pubkey.o src/uint256.o src/utilstrencodings.o src/arith_uint256.o secp256k1/src/secp256k1.o inc/crypto/ripemd160.o inc/crypto/sha256.o inc/crypto/sha512.o inc/crypto/hmac_sha512.o src/hash.o inc/script/standard.o inc/script/script.o inc/script/script_error.o src/keystore.o inc/primitives/transaction.o inc/script/ismine.o inc/script/interpreter.o inc/crypto/sha1.o inc/script/sign.o inc/univalue/lib/univalue.o src/bech32.o inc/univalue/lib/univalue_get.o inc/univalue/lib/univalue_read.o inc/univalue/lib/univalue_write.o inc/support/cleanse.o inc/primitives/block.o src/netaddress.o src/protocol.o inc/consensus/merkle.o src/chainparams.o src/chainparamsbase.o src/base58.o
LIBS     = -L"/usr/lib" -L"/usr/local/lib"
INCS     = -I"./inc" -I"./secp256k1/include" -I"./inc/univalue/include"
CXXINCS  = -I"./inc" -I"./secp256k1/include" -I"./inc/univalue/include"
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

inc/primitives/transaction.o: inc/primitives/transaction.cpp
	$(CPP) -c inc/primitives/transaction.cpp -o inc/primitives/transaction.o $(CXXFLAGS)

inc/script/ismine.o: inc/script/ismine.cpp
	$(CPP) -c inc/script/ismine.cpp -o inc/script/ismine.o $(CXXFLAGS)

inc/script/interpreter.o: inc/script/interpreter.cpp
	$(CPP) -c inc/script/interpreter.cpp -o inc/script/interpreter.o $(CXXFLAGS)

inc/crypto/sha1.o: inc/crypto/sha1.cpp
	$(CPP) -c inc/crypto/sha1.cpp -o inc/crypto/sha1.o $(CXXFLAGS)

inc/script/sign.o: inc/script/sign.cpp
	$(CPP) -c inc/script/sign.cpp -o inc/script/sign.o $(CXXFLAGS)

inc/univalue/lib/univalue.o: inc/univalue/lib/univalue.cpp
	$(CPP) -c inc/univalue/lib/univalue.cpp -o inc/univalue/lib/univalue.o $(CXXFLAGS)

src/bech32.o: src/bech32.cpp
	$(CPP) -c src/bech32.cpp -o src/bech32.o $(CXXFLAGS)

inc/univalue/lib/univalue_get.o: inc/univalue/lib/univalue_get.cpp
	$(CPP) -c inc/univalue/lib/univalue_get.cpp -o inc/univalue/lib/univalue_get.o $(CXXFLAGS)

inc/univalue/lib/univalue_read.o: inc/univalue/lib/univalue_read.cpp
	$(CPP) -c inc/univalue/lib/univalue_read.cpp -o inc/univalue/lib/univalue_read.o $(CXXFLAGS)

inc/univalue/lib/univalue_write.o: inc/univalue/lib/univalue_write.cpp
	$(CPP) -c inc/univalue/lib/univalue_write.cpp -o inc/univalue/lib/univalue_write.o $(CXXFLAGS)

inc/support/cleanse.o: inc/support/cleanse.cpp
	$(CPP) -c inc/support/cleanse.cpp -o inc/support/cleanse.o $(CXXFLAGS)

inc/primitives/block.o: inc/primitives/block.cpp
	$(CPP) -c inc/primitives/block.cpp -o inc/primitives/block.o $(CXXFLAGS)

src/netaddress.o: src/netaddress.cpp
	$(CPP) -c src/netaddress.cpp -o src/netaddress.o $(CXXFLAGS)

src/protocol.o: src/protocol.cpp
	$(CPP) -c src/protocol.cpp -o src/protocol.o $(CXXFLAGS)

inc/consensus/merkle.o: inc/consensus/merkle.cpp
	$(CPP) -c inc/consensus/merkle.cpp -o inc/consensus/merkle.o $(CXXFLAGS)

src/chainparams.o: src/chainparams.cpp
	$(CPP) -c src/chainparams.cpp -o src/chainparams.o $(CXXFLAGS)

src/chainparamsbase.o: src/chainparamsbase.cpp
	$(CPP) -c src/chainparamsbase.cpp -o src/chainparamsbase.o $(CXXFLAGS)

src/base58.o: src/base58.cpp
	$(CPP) -c src/base58.cpp -o src/base58.o $(CXXFLAGS)


