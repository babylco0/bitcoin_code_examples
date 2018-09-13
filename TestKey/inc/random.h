
#ifndef BITCOIN_RANDOM_H
#define BITCOIN_RANDOM_H
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */
/**
 * Function to gather random data from multiple sources, failing whenever any
 * of those source fail to provide a result.
 */

// Just For Test. Return "9a9a6539856be209b8ea2adbd155c0919646d108515b60b7b13d6a79f1ae5174"
unsigned char testPriKey[32] = {0x9a, 0x9a, 0x65, 0x39, 0x85, 0x6b, 0xe2, 0x09,
								0xb8, 0xea, 0x2a, 0xdb, 0xd1, 0x55, 0xc0, 0x91,
								0x96, 0x46, 0xd1, 0x08, 0x51, 0x5b, 0x60, 0xb7,
								0xb1, 0x3d, 0x6a, 0x79, 0xf1, 0xae, 0x51, 0x74};
void GetStrongRandBytes(unsigned char* buf, int num){
	int ii;
	for(ii = 0; ii < num; ii++){
		if(ii < 32){
			buf[ii] = testPriKey[ii];
		}
		else{
			buf[ii] = 0x00;
		}
	}
}

void GetRandBytes(unsigned char* buf, int num){
	/* initialize random seed: */
  	srand (time(NULL));
	for(int ii = 0; ii < num; ii++){
		/* generate secret number between 0 and 255: */
		buf[ii] = rand() % 256; 
	}
}
#endif
