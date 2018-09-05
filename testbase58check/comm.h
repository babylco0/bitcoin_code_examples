#ifndef TEST_BITCOIN_COMM_H
#define TEST_BITCOIN_COMM_H

/** 通用函数 */
// 返回16进制字符代表的整型值
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
}

#endif