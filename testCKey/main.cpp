#include <iostream>
#include <iomanip>

#include <key.h>
#include <pubkey.h>
#include <uint256.h>

int main(int argc, char** argv) {
	//9a9a6539856be209b8ea2adbd155c0919646d108515b60b7b13d6a79f1ae5174
	unsigned char testPriKey[32] = {0x9a, 0x9a, 0x65, 0x39, 0x85, 0x6b, 0xe2, 0x09,
								0xb8, 0xea, 0x2a, 0xdb, 0xd1, 0x55, 0xc0, 0x91,
								0x96, 0x46, 0xd1, 0x08, 0x51, 0x5b, 0x60, 0xb7,
								0xb1, 0x3d, 0x6a, 0x79, 0xf1, 0xae, 0x51, 0x74};
	//0340a609475afa1f9a784cad0db5d5ba7dbaab2147a5d7b9bbde4d1334a0e40a5e
	std::vector<unsigned char> testPubKey = {0x03, 0x40, 0xa6, 0x09, 0x47, 0x5a, 0xfa, 0x1f, 0x9a,
								0x78, 0x4c, 0xad, 0x0d, 0xb5, 0xd5, 0xba, 0x7d, 
								0xba, 0xab, 0x21, 0x47, 0xa5, 0xd7, 0xb9, 0xbb, 
								0xde, 0x4d, 0x13, 0x34, 0xa0, 0xe4, 0x0a, 0x5e};
	CPrivKey LoadPriKey;
	 
	CKey priKey;
	//priKey.MakeNewKey(true);
	ECCVerifyHandle eccVerifyHandle ;
	ECC_Start();
	// 设置私钥数据 
	priKey.Set(testPriKey, testPriKey+sizeof(testPriKey), true);	
	LoadPriKey = priKey.GetPrivKey();
	std::cout<<std::setw(2)<<std::hex;
    std::cout<<std::setfill('0');
	// 打印私钥 
	std::cout<<"Private key [0x"<<priKey.size()<<"]:";
	for(int ii = 0; ii < priKey.size(); ii++)
    {
        std::cout<<std::setw(2)<<std::hex;
        std::cout<<(int)(*(priKey.begin() + ii));
    }
	std::cout<<std::endl;
	// 获取公钥 
	CPubKey pubKey(testPubKey);	
	// 打印公钥 
	std::cout<<"Public key  [0x"<<pubKey.size()<<"]:";
	for(int ii = 0; ii < pubKey.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(pubKey.begin() + ii));
    }
	std::cout<<std::endl;
	// 检测公私钥是否匹配 
	if(priKey.VerifyPubKey(pubKey)){
		std::cout<<"Private Key vs. Public Key Match."<<std::endl;
	}
	// 获取公钥 Hash-160
	uint160 hash160 = pubKey.GetID(); 
	// 打印公钥 Hash-160
	std::cout<<"Hash-160    [0x"<<hash160.size()<<"]:";
	for(int ii = 0; ii < hash160.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(hash160.begin() + ii));
    }
	std::cout<<std::endl;
	// 获取公钥哈希值 
	uint256 hash = pubKey.GetHash();
	// 打印公钥哈希值  
	std::cout<<"Hash        [0x"<<hash.size()<<"]:";
	for(int ii = 0; ii < hash.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(hash.begin() + ii));
    }
	std::cout<<std::endl;
	std::vector<unsigned char> vchSig; 
	priKey.Sign(hash, vchSig);
	// 打印签名
	std::cout<<"Sign        [0x"<<vchSig.size()<<"]:"; 
	for(int ii = 0; ii < vchSig.size(); ii++){
		std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(vchSig.begin() + ii));
	}
	std::cout<<std::endl;
	
	// 校验签名 
	if(pubKey.CheckLowS(vchSig) && pubKey.Verify(hash, vchSig)){
		std::cout<<"Public Key Signed."<<std::endl;
	}
	// 获取非压缩公钥 
	pubKey.Decompress();
	// 打印公钥 
	std::cout<<"Public key  [0x"<<pubKey.size()<<"]:";
	for(int ii = 0; ii < pubKey.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(pubKey.begin() + ii));
    }
	std::cout<<std::endl;
	
	priKey.SignCompact(hash, vchSig);
	pubKey.RecoverCompact(hash, vchSig);
	// 打印公钥 
	std::cout<<"Public key Recovered From SignCompact  [0x"<<pubKey.size()<<"]:";
	for(int ii = 0; ii < pubKey.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(pubKey.begin() + ii));
    }
	std::cout<<std::endl;
	if(priKey.Load(LoadPriKey, pubKey, true)){
		std::cout<<"Load private key ok."<<std::endl;
	}
	// 获取子私钥 
	CKey keyChild;
	CPubKey pubkeyChild;
	ChainCode ccChild;
	unsigned int nChild = 1;
	ChainCode cc = hash;
	std::cout<<std::setw(100);
    std::cout<<std::endl<<std::setfill('=')<<"="<<std::endl;
	while(nChild <= 5){
		std::cout<<"Child key: [0x";
		std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<nChild<<"]"<<std::endl;
        std::cout<<"------------------------------------"<<std::endl;
		if(priKey.Derive(keyChild, ccChild, nChild, cc)){
			// 打印私钥 
			std::cout<<"Private key  [0x"<<pubKey.size()<<"]:";
			for(int ii = 0; ii < keyChild.size(); ii++)
		    {
		        std::cout<<std::setw(2);
		        std::cout<<std::setfill('0')<<std::hex<<(int)(*(keyChild.begin() + ii));
		    }
		    std::cout<<std::endl;
		}
		if(pubKey.Derive(pubkeyChild, ccChild, nChild, cc)){
			// 打印公钥 
			std::cout<<"Public key   [0x"<<pubkeyChild.size()<<"]:";
			for(int ii = 0; ii < pubkeyChild.size(); ii++)
		    {
		        std::cout<<std::setw(2);
		        std::cout<<std::setfill('0')<<std::hex<<(int)(*(pubkeyChild.begin() + ii));
		    }
			std::cout<<std::endl;
		}
		// 验证公钥私钥是否匹配 
		if(!priKey.VerifyPubKey(pubKey)){
			break;
		}
		cc = ccChild;
		nChild++;
		std::cout<<"------------------------------------"<<std::endl;
	}	
	std::cout<<std::setw(100);
    std::cout<<std::endl<<std::setfill('=')<<"="<<std::endl;
	ECC_Stop();
	return 0;
}
