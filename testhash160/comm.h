#ifndef TEST_BITCOIN_COMM_H
#define TEST_BITCOIN_COMM_H
#include <stdint.h>
#include <string.h>
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
/***************************************************************************/
/** 大小端数据处理函数 */
// 以字节为单位交换数据的高低位 
inline uint64_t bswap_64(uint64_t x)
{
     return (((x & 0xff00000000000000ull) >> 56)
          | ((x & 0x00ff000000000000ull) >> 40)
          | ((x & 0x0000ff0000000000ull) >> 24)
          | ((x & 0x000000ff00000000ull) >> 8)
          | ((x & 0x00000000ff000000ull) << 8)
          | ((x & 0x0000000000ff0000ull) << 24)
          | ((x & 0x000000000000ff00ull) << 40)
          | ((x & 0x00000000000000ffull) << 56));
}
inline uint32_t bswap_32(uint32_t x)
{
    return (((x & 0xff000000U) >> 24) | ((x & 0x00ff0000U) >>  8) |
            ((x & 0x0000ff00U) <<  8) | ((x & 0x000000ffU) << 24));
}
// 大端模式与小端模式的转换 
inline uint32_t be32toh(uint32_t big_endian_32bits)
{
    return bswap_32(big_endian_32bits);
}
inline uint32_t htobe32(uint32_t host_32bits)
{
    return bswap_32(host_32bits);
}
inline uint64_t htobe64(uint64_t host_64bits)
{
    return bswap_64(host_64bits);
}
inline uint64_t le64toh(uint64_t little_endian_64bits)
{
    return little_endian_64bits;
}
inline uint32_t htole32(uint32_t host_32bits)
{
    return host_32bits;
}
inline uint32_t le32toh(uint32_t little_endian_32bits)
{
    return little_endian_32bits;
}
inline uint64_t htole64(uint64_t host_64bits)
{
    return host_64bits;
}
uint32_t static inline ReadLE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return le32toh(x);
}
uint32_t static inline ReadBE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return be32toh(x);
}
void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htole32(x);
    memcpy(ptr, (char*)&v, 4);
}
void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htobe32(x);
    memcpy(ptr, (char*)&v, 4);
}
void static inline WriteLE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htole64(x);
    memcpy(ptr, (char*)&v, 8);
}
uint64_t static inline ReadLE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy((char*)&x, ptr, 8);
    return le64toh(x);
}
void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htobe64(x);
    memcpy(ptr, (char*)&v, 8);
}
/***************************************************************************/
#endif