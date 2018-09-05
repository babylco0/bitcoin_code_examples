#include "comm.h"
#include "testhash.h"
#include "testripemd160.h"

/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
    uint160() {}
    explicit uint160(const std::vector<unsigned char>& vch) : base_blob<160>(vch) {}
};

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash160& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash160& Reset() {
        sha.Reset();
        return *this;
    }
};
/** Compute the 160-bit hash an object. */
template<typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = {};
    uint160 result;
    CHash160().Write(pbegin == pend ? pblank : (const unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}


/** 测试主函数 */
int main(int argc, char *argv[]){
    unsigned char hexstr[] = "0340A609475AFA1F9A784CAD0DB5D5BA7DBAAB2147A5D7B9BBDE4D1334A0E40A5E";
    int len = sizeof(hexstr) / 2;
    unsigned char udat[len];    

    for(int i = 0; i < sizeof(hexstr); i+=2){		
        udat[i/2] = hex2int(hexstr[i]) * 16 + hex2int(hexstr[i + 1]);
    }
    std::vector<unsigned char> vdat(udat, udat+sizeof(udat));
	std::cout<<"Data: "; 
	for(std::vector<unsigned char>::iterator iter = vdat.begin(); iter != vdat.end(); ++iter)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*iter);
    }
	std::cout<<std::endl;
    std::cout<<"RIPEMD-160: ";
    uint160 hash160 = Hash160(vdat.begin(), vdat.end());
    for(int i = 0; i < hash160.size(); i++){
		unsigned char* iter = (unsigned char*)&hash160 + i;
		std::cout<<std::setfill('0')<<std::hex<<(int)(*iter);
	}
	std::cout<<std::endl; 
    return 0;
}