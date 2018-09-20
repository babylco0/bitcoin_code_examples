#include <iostream>
#include <iomanip>

#include <key.h>
#include <pubkey.h>
#include <keystore.h>
#include <uint256.h>
#include <script/standard.h>
#include <script/script.h>
#include <script/ismine.h>
#include <base58.h>
#include <netaddress.h>
#include <protocol.h>
#include <base58.h>
#include <chainparams.h>
#include <utilstrencodings.h>

#include <core_io.h>
#include <consensus/validation.h>

// 打印n个x字符 
void print_line(int n, char x){
	std::cout<<std::endl<<std::setw(n);
    std::cout<<std::setfill(x)<<" "<<std::endl;
}

// 打印容器
template<typename T1>
void print_vector(const T1 pos, int size){
	unsigned char *begin = (unsigned char*)&pos[0];
	for(int ii = 0; ii < size; ii++){
		std::cout<<std::setw(2);
		std::cout<<std::setfill('0')<<std::hex<<(int)(*(begin + ii));
	}
	print_line(20, '-');
} 

/**
 * 测试密钥对
 * 私钥：9a9a6539856be209b8ea2adbd155c0919646d108515b60b7b13d6a79f1ae5174
 * 公钥：0340a609475afa1f9a784cad0db5d5ba7dbaab2147a5d7b9bbde4d1334a0e40a5e
 */ 
std::vector<unsigned char> TestPriKey = {
										0x9a, 0x9a, 0x65, 0x39, 0x85, 0x6b, 0xe2, 0x09,
										0xb8, 0xea, 0x2a, 0xdb, 0xd1, 0x55, 0xc0, 0x91,
										0x96, 0x46, 0xd1, 0x08, 0x51, 0x5b, 0x60, 0xb7,
										0xb1, 0x3d, 0x6a, 0x79, 0xf1, 0xae, 0x51, 0x74
										};
std::vector<unsigned char> TestPubKey = {0x03, 
										0x40, 0xa6, 0x09, 0x47, 0x5a, 0xfa, 0x1f, 0x9a,
										0x78, 0x4c, 0xad, 0x0d, 0xb5, 0xd5, 0xba, 0x7d, 
										0xba, 0xab, 0x21, 0x47, 0xa5, 0xd7, 0xb9, 0xbb, 
										0xde, 0x4d, 0x13, 0x34, 0xa0, 0xe4, 0x0a, 0x5e
										};
/**
 * Alice:
 * PriKey: 6bce49ff84094382d822178de357a435f85e8ad8fdfa39bd58aa2e5192267198
 * PubKey: 03e3bd2f408e4415aa57c747f6550937823a8605706c358facdc6325b4a99f2161
 */
std::vector<unsigned char> TestPriKeyA = {
										0x6b, 0xce, 0x49, 0xff, 0x84, 0x09, 0x43, 0x82, 
										0xd8, 0x22, 0x17, 0x8d, 0xe3, 0x57, 0xa4, 0x35, 
										0xf8, 0x5e, 0x8a, 0xd8, 0xfd, 0xfa, 0x39, 0xbd, 
										0x58, 0xaa, 0x2e, 0x51, 0x92, 0x26, 0x71, 0x98
										};
std::vector<unsigned char> TestPubKeyA = {0x03, 
										0xe3, 0xbd, 0x2f, 0x40, 0x8e, 0x44, 0x15, 0xaa, 
										0x57, 0xc7, 0x47, 0xf6, 0x55, 0x09, 0x37, 0x82, 
										0x3a, 0x86, 0x05, 0x70, 0x6c, 0x35, 0x8f, 0xac, 
										0xdc, 0x63, 0x25, 0xb4, 0xa9, 0x9f, 0x21, 0x61
										};
/**
 * Bob:
 * PriKey: 3e46c724c8e9728379a9cab2ec46030563f06d7e0ace2b734b5861b8f64b6f2f
 * PubKey: 020e80933a750e84b4c35c10bc797ca34d1c885e4e65531a7499170a1c78ffdd97
 */	
std::vector<unsigned char> TestPriKeyB = {
										0x3e, 0x46, 0xc7, 0x24, 0xc8, 0xe9, 0x72, 0x83, 
										0x79, 0xa9, 0xca, 0xb2, 0xec, 0x46, 0x03, 0x05, 
										0x63, 0xf0, 0x6d, 0x7e, 0x0a, 0xce, 0x2b, 0x73, 
										0x4b, 0x58, 0x61, 0xb8, 0xf6, 0x4b, 0x6f, 0x2f
										};								
std::vector<unsigned char> TestPubKeyB = {0x02, 
										0x0e, 0x80, 0x93, 0x3a, 0x75, 0x0e, 0x84, 0xb4, 
										0xc3, 0x5c, 0x10, 0xbc, 0x79, 0x7c, 0xa3, 0x4d, 
										0x1c, 0x88, 0x5e, 0x4e, 0x65, 0x53, 0x1a, 0x74, 
										0x99, 0x17, 0x0a, 0x1c, 0x78, 0xff, 0xdd, 0x97
										};
/**
 * Martin:
 * PriKey: bfe5647b87c61058969bbe599879c49372fa0d6e2bfc71125960e3c1de5fbc0b
 * PubKey: 039155f9024807d126be4df4d09273c5fece4767e89b4527c68b48414a2877eddd
 */	
std::vector<unsigned char> TestPriKeyM = {
										0xbf, 0xe5, 0x64, 0x7b, 0x87, 0xc6, 0x10, 0x58, 
										0x96, 0x9b, 0xbe, 0x59, 0x98, 0x79, 0xc4, 0x93, 
										0x72, 0xfa, 0x0d, 0x6e, 0x2b, 0xfc, 0x71, 0x12, 
										0x59, 0x60, 0xe3, 0xc1, 0xde, 0x5f, 0xbc, 0x0b
										};								
std::vector<unsigned char> TestPubKeyM = {0x03, 
										0x91, 0x55, 0xf9, 0x02, 0x48, 0x07, 0xd1, 0x26, 
										0xbe, 0x4d, 0xf4, 0xd0, 0x92, 0x73, 0xc5, 0xfe, 
										0xce, 0x47, 0x67, 0xe8, 0x9b, 0x45, 0x27, 0xc6, 
										0x8b, 0x48, 0x41, 0x4a, 0x28, 0x77, 0xed, 0xdd
										};	
										
/**
 * Debug tansaction hex 
 */
std::string TestHexTx = "02000000000101991816e3bd6bb9faf77b836560f01d433d4819dbb3499120a3"\
						"704c69b4d73f4200000000232200206f0f2d495c106ccb69b10a8f57ca115674"\
						"d0f302fa918b29df65e464b132c18dffffffff0158a007000000000017a9147c"\
						"7020ed135a05c86bcec1c491426eec48efb2a9870400483045022100cf5d6620"\
						"11e226a82d8cb860290565acfe42cd332a16d2c4c81a60fa01b3c37802201983"\
						"bd20263889acc18c06a47ee36cf77c6594fd1b0ddf8f9d20b954071bda170147"\
						"304402205637494e4efbe71052d084f133c81f6af7d134170f12b546c3ca926f"\
						"f80bbff9022037bffc1e9cba1c485032d5fc6cf92f73d8fe76295c467ff48b0b"\
						"9cdcfe2a52010169522103e3bd2f408e4415aa57c747f6550937823a8605706c"\
						"358facdc6325b4a99f216121020e80933a750e84b4c35c10bc797ca34d1c885e"\
						"4e65531a7499170a1c78ffdd9721039155f9024807d126be4df4d09273c5fece"\
						"4767e89b4527c68b48414a2877eddd53ae00000000";	
std::string TestHexTx2 = "0200000000010176345c521e457a604000b1543aaa6bcdfef274bb614662f363"\
						 "c3b63ba0d6f1f300000000171600148e0d7aae920edda41e3fd0ae89fe0f8460"\
						 "c3132ffdffffff0220a107000000000017a914910eb5b15177193bad6bf65216"\
						 "a969289aca0ba1877aa007000000000017a914f1e97dd31778893c6f31a94f83"\
						 "ea7cb9b5340498870247304402202aa82440092153d4a316c31048f5e794a7ba"\
						 "96b2b217d77610127fca2661981e0220515d4d189918a889cb4c90aac71603a7"\
						 "c3f108f806ab2e41c23a5ca65c9c0ee7012103e3bd2f408e4415aa57c747f655"\
						 "0937823a8605706c358facdc6325b4a99f2161247d1500";																		

// 公私钥测试程序 
int main_keytest() {

	CPrivKey LoadPriKey;	 
	CKey priKey;
	//priKey.MakeNewKey(true);
	ECCVerifyHandle eccVerifyHandle ;
	ECC_Start();
	// 设置私钥数据 
	priKey.Set(TestPriKey.begin(), TestPriKey.end(), true);	
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
    print_line(20, '-');
	// 获取公钥 
	CPubKey pubKey(TestPubKey);	
	// 打印公钥 
	std::cout<<"Public key  [0x"<<pubKey.size()<<"]:";
	for(int ii = 0; ii < pubKey.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(pubKey.begin() + ii));
    }
	print_line(20, '-');
	// 检测公私钥是否匹配 
	if(priKey.VerifyPubKey(pubKey)){
		std::cout<<"***** Private Key vs. Public Key Match. *****";
	}
	print_line(20, '-');
	// 获取公钥 Hash-160
	CKeyID hash160 = pubKey.GetID(); 
	// 打印公钥 Hash-160
	std::cout<<"Hash-160    [0x"<<hash160.size()<<"]:";
	for(int ii = 0; ii < hash160.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(hash160.begin() + ii));
    }
	print_line(20, '-');
	// 获取公钥哈希值 
	uint256 hash = pubKey.GetHash();
	// 打印公钥哈希值  
	std::cout<<"Hash        [0x"<<hash.size()<<"]:";
	for(int ii = 0; ii < hash.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(hash.begin() + ii));
    }
	print_line(20, '-');
	std::vector<unsigned char> vchSig; 
	priKey.Sign(hash, vchSig);
	// 打印签名
	std::cout<<"Sign        [0x"<<vchSig.size()<<"]:"; 
	for(int ii = 0; ii < vchSig.size(); ii++){
		std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(vchSig.begin() + ii));
	}
	print_line(20, '-');
	
	// 校验签名 
	if(pubKey.CheckLowS(vchSig) && pubKey.Verify(hash, vchSig)){
		std::cout<<"**** Public Key Verify Sign Ok. ****";
	}
	print_line(20, '-');
	// 获取非压缩公钥 
	pubKey.Decompress();
	// 打印公钥 
	std::cout<<"**** Public key Decompressed ****"<<std::endl;
	std::cout<<"Public key  [0x"<<pubKey.size()<<"]:";
	for(int ii = 0; ii < pubKey.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(pubKey.begin() + ii));
    }
	print_line(20, '-');
	
	priKey.SignCompact(hash, vchSig);
	pubKey.RecoverCompact(hash, vchSig);
	// 打印公钥 
	std::cout<<"**** Public key Recovered From SignCompact ****"<<std::endl;
	std::cout<<"Public key  [0x"<<pubKey.size()<<"]:";
	for(int ii = 0; ii < pubKey.size(); ii++)
    {
        std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<(int)(*(pubKey.begin() + ii));
    }
	print_line(20, '-');
	if(priKey.Load(LoadPriKey, pubKey, true)){
		std::cout<<"**** Load private key ok. ****";
	}
	print_line(20, '-');
	// 获取子私钥 
	CKey keyChild;
	CPubKey pubkeyChild;
	ChainCode ccChild;
	unsigned int nChild = 1;
	ChainCode cc = hash;
	while(nChild <= 5){
		std::cout<<"Child key: [0x";
		std::cout<<std::setw(2);
        std::cout<<std::setfill('0')<<std::hex<<nChild<<"]";
        print_line(20, '-');
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
		}
		// 验证公钥私钥是否匹配 
		if(!priKey.VerifyPubKey(pubKey)){
			break;
		}
		cc = ccChild;
		nChild++;
		print_line(20, '-');
	}	
	ECC_Stop();
	return 0;
}
/* 公私钥测试程序结束 */ 

// 脚本生成测试程序
int main_scripttest(){	
	// 设置公钥 
	CPubKey pubKey(TestPubKey);	
	/** 从公钥生成一个P2PK脚本 */
	CScript P2PK = GetScriptForRawPubKey(pubKey);
	std::cout<<"**** P2PK:"<<std::endl;
	for(int ii = 0; ii < P2PK.size(); ii++){
		std::cout<<std::setw(2);
		std::cout<<std::setfill('0')<<std::hex<<(int)(*(P2PK.begin() + ii));
	}
	print_line(20, '-'); 
	/** 生成一个P2WPKH脚本 */
	CScript P2WPKH = GetScriptForWitness(P2PK);
	std::cout<<"**** P2WPKH:"<<std::endl;	
	for(int ii = 0; ii < P2WPKH.size(); ii++){
		std::cout<<std::setw(2);
		std::cout<<std::setfill('0')<<std::hex<<(int)(*(P2WPKH.begin() + ii));
	}
	print_line(20, '-');
	/* 生成一个脚本公钥 */
	CScript scriptPubKey = GetScriptForDestination(P2WPKH);
	std::cout<<"**** Bitcoin scriptPubKey:"<<std::endl;
	if(!scriptPubKey.IsPayToScriptHash()){
		std::cout<<" Error :";
	}
	for(int ii = 0; ii < scriptPubKey.size(); ii++){
		std::cout<<std::setw(2);
		std::cout<<std::setfill('0')<<std::hex<<(int)(*(scriptPubKey.begin() + ii));
	}
	print_line(20, '-'); 
	/** 生成一个多签名脚本 */
	std::vector<CPubKey> keys ={CPubKey(TestPubKeyA), CPubKey(TestPubKeyB), CPubKey(TestPubKeyM)};
	CScript mnScript = GetScriptForMultisig(2, keys);
	std::cout<<"**** Multisig script:"<<std::endl;
	for(int ii = 0; ii < mnScript.size(); ii++){
		std::cout<<std::setw(2);
		std::cout<<std::setfill('0')<<std::hex<<(int)(*(mnScript.begin() + ii));
	}
	print_line(20, '-');
	/* 从多签名脚本生成脚本公钥 */
	scriptPubKey = GetScriptForDestination(mnScript);
	std::cout<<"**** Bitcoin scriptPubKey:"<<std::endl;
	for(int ii = 0; ii < scriptPubKey.size(); ii++){
		std::cout<<std::setw(2);
		std::cout<<std::setfill('0')<<std::hex<<(int)(*(scriptPubKey.begin() + ii));
	}
	print_line(20, '-');
	/* 解析多签名脚本信息 */
	txnouttype typeRet;							// 脚本类型 
	std::vector<CTxDestination> addressRet;		// 脚本地址信息 
	int nRequiredRet;							// 需要签名数量 
	if(ExtractDestinations(mnScript, typeRet, addressRet, nRequiredRet)){
		std::cout<<"**** Type:"<<GetTxnOutputType(typeRet)<<std::endl;
		std::cout<<"**** Required: "<<nRequiredRet<<" / "<<addressRet.size();	
		print_line(20, '-');	
		for(int ii = 0; ii < addressRet.size(); ii++){
			std::cout<<"**** Address script: "<<ii<<": "<<std::endl;
			if(!IsValidDestination(addressRet[ii])){
				break;
			}
			CScript script = GetScriptForDestination(addressRet[ii]);
			P2WPKH = GetScriptForWitness(script);
			for(int ij = 0; ij < P2WPKH.size(); ij++){
				std::cout<<std::setw(2);
				std::cout<<std::setfill('0')<<std::hex<<(int)(*(P2WPKH.begin() + ij));
			}
			print_line(20, '-');
		}
	}
	return 0;
} 
/** 脚本生成测试程序结束 */ 

// 密钥存储测试程序
int main_keystoretest(){
	ECCVerifyHandle eccVerifyHandle ;
	ECC_Start();
	// 创建一个密钥存储 
	CBasicKeyStore keystore; 
	CKey priKey;
	CPubKey pubKey;
	// 添加一个密钥对
	priKey.Set(TestPriKey.begin(), TestPriKey.end(), true);
	pubKey.Set(TestPubKey.begin(), TestPubKey.end());
	keystore.AddKeyPubKey(priKey, pubKey);
	priKey.Set(TestPriKeyA.begin(), TestPriKeyA.end(), true);
	pubKey.Set(TestPubKeyA.begin(), TestPubKeyA.end());
	keystore.AddKeyPubKey(priKey, pubKey);
	priKey.Set(TestPriKeyB.begin(), TestPriKeyB.end(), true);
	pubKey.Set(TestPubKeyB.begin(), TestPubKeyB.end());
	keystore.AddKeyPubKey(priKey, pubKey);
	// 获取所有密钥对 
	CKey priKey1;
	CPubKey pubKey1;
	int count = 0;
	std::set<CKeyID> keys = keystore.GetKeys(); 
	for(std::set<CKeyID>::iterator it = keys.begin(); it != keys.end(); it++){
		std::cout<<"**** Key "<<count++<<std::endl;
		if(keystore.GetKey(*it, priKey1)){
			std::cout<<"Private key:";
			print_vector(priKey1.begin(), priKey1.size());
		}
		if(keystore.GetPubKey(*it, pubKey1)){
			std::cout<<"Public key:";
			print_vector(pubKey1, pubKey.size());
		}
	}

	pubKey.Set(TestPubKey.begin(), TestPubKey.end());
	CKeyID address = pubKey.GetID(); 
	// 添加脚本
	CScript script = GetScriptForDestination(WitnessV0KeyHash(address)); 
	CScriptID hash(script);
	// 根据脚本获取key 
	address = GetKeyForDestination(keystore, script);
	std::cout<<"**** Address: ";
	print_vector(address.begin(), address.size());
	// 添加密钥对时已添加对应得脚本，所以存储中已存在脚本 
	if(keystore.HaveCScript(hash)){
		std::cout<<"**** Have script: ";
		print_vector(hash.begin(), hash.size());
	}
	// 通过脚本哈希值获取脚本	
	if(keystore.GetCScript(hash, script)){
		std::cout<<"**** Get script: ";
		print_vector(script, script.size());
	} 
	
	// 只看脚本
	if(!keystore.HaveWatchOnly(script)){
		keystore.AddWatchOnly(script);
		if(keystore.HaveWatchOnly(script)){
			std::cout<<"**** Watch:";
			print_vector(script, script.size());
		}		
	}
		
	// 查看Ismine类型 
	std::cout<<"Ismine type: "<<IsMine(keystore, script)<<std::endl;
	//std::cout<<EncodeBase58Check(CScriptID(script))<<std::endl;
	ECC_Stop();
	return 0;
} 

// Base58Check Encode/Decode Destination
int main_bs58check(){
	// 选择主网参数 
	SelectParams(CBaseChainParams::MAIN);
	// 设置测试密钥
	CKey priKey;
	CPubKey pubKey;
	priKey.Set(TestPriKey.begin(), TestPriKey.end(), true);
	pubKey.Set(TestPubKey.begin(), TestPubKey.end());
	CKeyID address = pubKey.GetID(); 
	// 打印公钥ID
	std::cout<<"**** Pubkey ID:";
	print_vector(address.begin(), address.size());
	// 打印编码的比特币地址 
	std::cout<<"**** Encode Destination ****"<<std::endl; 
	std::string destPubKey = EncodeDestination(address);
	std::cout<<"****   P2PK Address: ";
	std::cout<<destPubKey<<std::endl;
	CScript P2WPKH = GetScriptForDestination(WitnessV0KeyHash(address)); 
	std::string destP2WPKH = EncodeDestination(P2WPKH);
	std::cout<<"**** P2WPKH Address: ";
	std::cout<<destP2WPKH<<std::endl; 
	std::string bech32P2WPKH = EncodeDestination(WitnessV0KeyHash(address));
	std::cout<<"**** Bech32 P2WPKH Address: ";
	std::cout<<bech32P2WPKH<<std::endl; 	
	uint256 hash;
    CSHA256().Write(&P2WPKH[0], P2WPKH.size()).Finalize(hash.begin());
	std::string bech32P2WSH = EncodeDestination(WitnessV0ScriptHash(hash));
	std::cout<<"****  Bech32 P2WSH Address: ";
	std::cout<<bech32P2WSH<<std::endl; 
	print_line(100, '=');
	std::cout<<"**** Decode Destination ****"<<std::endl; 
	// 解码P2PK地址 
	if(IsValidDestinationString(destPubKey)){
		CTxDestination ctxDest = DecodeDestination(destPubKey);
		CScript scriptPubKey = GetScriptForDestination(ctxDest);
		std::cout<<"****   P2PK scriptPubKey: ";
		print_vector(scriptPubKey, scriptPubKey.size());
	}
	// 解码P2WPK地址 
	CChainParams params = *CreateChainParams(CBaseChainParams::MAIN);
	if(IsValidDestinationString(destP2WPKH, params)){
		CTxDestination ctxDest = DecodeDestination(destP2WPKH);
		CScript scriptPubKey = GetScriptForDestination(ctxDest);
		std::cout<<"**** P2WPKH scriptPubKey: ";
		print_vector(scriptPubKey, scriptPubKey.size());
	}
	// 解码bech32格式地址 
	if(IsValidDestinationString(bech32P2WPKH)){
		CTxDestination ctxDest = DecodeDestination(bech32P2WPKH);
		CScript scriptPubKey = GetScriptForDestination(ctxDest);
		std::cout<<"**** Bech32 P2WPKH scriptPubKey: ";
		print_vector(scriptPubKey, scriptPubKey.size());
	}
	if(IsValidDestinationString(bech32P2WSH)){
		CTxDestination ctxDest = DecodeDestination(bech32P2WSH);
		CScript scriptPubKey = GetScriptForDestination(ctxDest);
		std::cout<<"****  Bech32 P2WSH scriptPubKey: ";
		print_vector(scriptPubKey, scriptPubKey.size());
	}
	
	return 0;
}
/** Base58Check Encode/Decode Destination 结束*/

// Decode Hex Transaction
int main_decodetx(){
	CMutableTransaction tx;		// 结构体格式 
	// 解码十六进制格式交易ID 
	if(DecodeHexTx(tx, TestHexTx2)){
		CTransaction ctx(tx);
		std::cout<<"**** CTrasnaction:"<<std::endl;
		print_line(100, '=');
		std::cout<<"\"txid\": "<<ctx.GetHash().ToString()<<std::endl;
		std::cout<<"\"hash\": "<<ctx.GetWitnessHash().ToString()<<std::endl;
		std::cout<<"\"version\": "<<ctx.nVersion<<std::endl;
		std::cout<<"\"size\": "<<ctx.GetTotalSize()<<std::endl;
		std::cout<<"\"vsize\": "<<((GetTransactionWeight(ctx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR)<<std::endl;
		std::cout<<"\"locktime\": "<<ctx.nLockTime<<std::endl;
		// vin 信息 
		std::cout<<"\"vin\"["<<std::endl;
		for (const auto& tx_in : ctx.vin){
			std::cout<<"  {"<<std::endl;
			std::cout<<"    \"txid\": "<<tx_in.prevout.hash.ToString()<<std::endl;;
			std::cout<<"    \"vout\": "<<tx_in.prevout.n<<std::endl;
			std::cout<<"    \"scriptSig\": {"<<std::endl;
			std::cout<<"      \"asm\": "<<ScriptToAsmStr(tx_in.scriptSig)<<std::endl;
			std::cout<<"      \"hex\": "<<HexStr(tx_in.scriptSig)<<std::endl;
			std::cout<<"      }"<<std::endl;
			std::cout<<"    \"txinwitness\": ["<<std::endl;
			for (unsigned int i = 0; i < tx_in.scriptWitness.stack.size(); i++) {
		    	if (i) {
		            std::cout<<", "<<std::endl;
		        }
		        std::cout<<HexStr(tx_in.scriptWitness.stack[i]);
		    }
		    std::cout<<std::endl;
			std::cout<<"    ]"<<std::endl;
			std::cout<<"    \"sequence\": "<<tx_in.nSequence<<std::endl;
			std::cout<<"  }"<<std::endl;
		}
		std::cout<<"]"<<std::endl;
		// vout 信息 
		std::cout<<"\"vout\"["<<std::endl;
		int ivout = 0;
		for (const auto& tx_out : ctx.vout){
			std::cout<<"    {"<<std::endl;
			std::cout<<"      \"value\": "<<(double)tx_out.nValue/COIN<<std::endl;
			std::cout<<"      \"n\": "<<ivout++<<std::endl;
			std::cout<<"      \"scriptPubKey\": {"<<std::endl;
			std::cout<<"      \"asm\": ";
			std::cout<<ScriptToAsmStr(tx_out.scriptPubKey)<<std::endl;
			std::cout<<"      \"hex\": ";
			std::cout<<HexStr(tx_out.scriptPubKey)<<std::endl;
			txnouttype typeRet;
			std::vector<CTxDestination> addressRet;
			int nRequiredRet;
			// 提取地址信息 
			if(ExtractDestinations(tx_out.scriptPubKey, typeRet, addressRet, nRequiredRet)){
				std::cout<<"       \"reqSigs\": "<<nRequiredRet<<std::endl;
				std::cout<<"       \"type\": "<<GetTxnOutputType(typeRet)<<std::endl;
			}
			std::cout<<"       \"addresses\": ["<<std::endl;
			// 设置参数为testnet 
			SelectParams(CBaseChainParams::TESTNET);
			for (const auto& address : addressRet)
				std::cout<<"          "<<EncodeDestination(address)<<std::endl;
			std::cout<<"        ]"<<std::endl;
			std::cout<<"      }"<<std::endl;
			std::cout<<"    }"<<std::endl;
		}
		std::cout<<"]"<<std::endl;
		// 编码交易ID为十六进制字符串 
		std::cout<<"**** HexTx:"<<std::endl;
		print_line(100, '=');
		std::cout<<EncodeHexTx(ctx)<<std::endl;
	}
	return 0;
}
/** End of Decode Hex Transaction */

/** 密钥存储测试程序结束 */ 
int main(int argc, char** argv){
	/** 公私钥测试程序 */
	/* 
	print_line(100, '='); 
	std::cout<<"Private Key & Public Key";
	print_line(100, '=');
	main_keytest();
	print_line(100, '=');
	*/
	/** 脚本生成测试程序 */ 
	/*
	print_line(100, '=');
	std::cout<<"Script";
	print_line(100, '=');
	main_scripttest();
	print_line(100, '=');
	*/
	/** 密钥存储 */ 
	/*
	print_line(100, '=');
	std::cout<<"Keystore";
	print_line(100, '=');
	main_keystoretest();
	print_line(100, '=');
	*/
	
	/** netaddress */
	/**
	in_addr ipv4Addr;
	ipv4Addr.s_addr = inet_addr("127.0.0.1");
	CNetAddr c_net_addr(ipv4Addr);
	std::cout<<c_net_addr.ToString();
	*/
	
	/** Base58Check Encode/Decode Destination */
	/*
	print_line(100, '=');
	std::cout<<"Base58Check Encode/Decode Destination";
	print_line(100, '=');
	main_bs58check();
	print_line(100, '=');
	*/
	
	/** Core Read/Write */
	/** Decode Hex Transaction */	
	print_line(100, '=');
	std::cout<<"Decode Hex Transaction";
	print_line(100, '=');
	main_decodetx();
	print_line(100, '=');
	
	return 0;
}
