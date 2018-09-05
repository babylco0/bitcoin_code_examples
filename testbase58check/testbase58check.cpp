
#include "comm.h"
#include "testhash.h"
#include "testbase58.h"

std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, ensure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet[vchRet.size() - 4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}

/** 测试主函数 */
int main(int argc, char* argv[]){
    unsigned char hexstr[] = "00154de7cabbb5822075e92c57a27ca3ef3e8be50c";

    unsigned char udat[sizeof(hexstr)/2];    

	  for(int i = 0; i < sizeof(hexstr); i+=2){		
		  udat[i/2] = hex2int(hexstr[i]) * 16 + hex2int(hexstr[i + 1]);
	  }
	  std::vector<unsigned char> vdat(udat, udat+sizeof(udat));
    std::string encode;
    std::vector<unsigned char> decode;
    encode = EncodeBase58Check(vdat);
    std::cout<<"Encode: "<<encode<<std::endl;
    if(DecodeBase58Check(encode, decode)){
        std::cout<<"Decode: ";
        for(std::vector<unsigned char>::iterator iter = decode.begin(); iter != decode.end(); ++iter)
        {
            std::cout<<std::setw(2);
            std::cout<<std::setfill('0')<<std::hex<<(int)(*iter);
        }
        std::cout<<std::endl;
    }
    else {
        std::cout<<"Decode error!"<<std::endl;
    }

    return 0;
}
