#include <iostream>
#include "include/secp256k1.h"
#include <iomanip>

/* run this program using the console pauser or add your own getch, system("pause") or input loop */
int hex2int(unsigned char x){
	if(x >= '0' && x <= '9'){
		return (x - '0');
	}
	if(x >= 'A' && x <= 'F'){
		return (x - 'A' + 10);
	}
	if(x >= 'a' && x <= 'f'){
		return (x - 'a' + 10);
	}
    return -1;
}
static secp256k1_context* secp256k1_context_sign = nullptr;
int main(int argc, char** argv) {
	unsigned char prikeyhex[] = "9a9a6539856be209b8ea2adbd155c0919646d108515b60b7b13d6a79f1ae5174";
    int len = sizeof(prikeyhex) / 2;
    unsigned char prikey[len];
    for(int i = 0; i < sizeof(prikeyhex); i+=2){		
        prikey[i/2] = hex2int(prikeyhex[i]) * 16 + hex2int(prikeyhex[i + 1]);
    }
    std::cout<<"Data: "; 
	for(int i = 0; i < len; i++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(prikey[i]);
    } 
    std::cout<<std::endl;
    //////////////////////////////////////////////////////////////
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context_sign = ctx;
    secp256k1_pubkey pubkey;
    for(int i = 0; i < 64; i++){
    	printf("%02x", pubkey.data[i]);
	}
	printf("\n");
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, prikey);
    printf("%02x",0x40);
    for(int i = 31; i >= 0; i--){
    	printf("%02x", pubkey.data[i]);
	}
	for(int i = 63; i >= 32; i--){
    	printf("%02x", pubkey.data[i]);
	}
	printf("\n0440a609475afa1f9a784cad0db5d5ba7dbaab2147a5d7b9bbde4d1334a0e40a5e188ac3f1c6bbbc336fdc33cb5e605ff7c3ee2d36249933b0322220a616a11fb3\n");
    return 0;
}
