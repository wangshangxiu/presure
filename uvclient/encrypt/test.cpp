#include"client.h"
#include "rsa_encrypt.h"
#include "aes_crypt.h"
 #include <string.h>
#include"comm.h"
int main(int argc, char* argv[])
{



	printf("\n-------------rsa test-------------------------------\n");
	//rsa demo test
	demoTest();



	//aes demo test
	printf("\n-------------aes test-------------------------------\n");
	aesDemoTest();
	//ecdh demo test

	printf("\n-------------ecdh test-------------------------------\n");
	 
	//生成一对公私钥ecdh，且16进制打印出来
	string  ecdhPubkey;
	string ecdhPrivateKey;

	generate_key_pair_public_private_ecdh_string(ecdhPubkey, ecdhPrivateKey);
	 
	char szBuf1[100] = "";
	char szBuf2[100] = "";
	printf("ecdhpubkey:%s-->privatekey:%s\n", hex2Str((char*)ecdhPubkey.c_str(), ecdhPubkey.length(), szBuf1), hex2Str((char*)ecdhPrivateKey.c_str(), ecdhPrivateKey.length(), szBuf2));
		
	//协商密码测试
	{
		string  ecdhPubkeyA;
		string ecdhPrivateKeyA;
		string  ecdhPubkeyB;
		string ecdhPrivateKeyB;
 
		//产生ecdh公私钥对 a
		generate_key_pair_public_private_ecdh_string(ecdhPubkeyA, ecdhPrivateKeyA);
		char tmpPub[67] = "";

		printf("\n--------A:pubkey:%s\n",hex2Str((char*)ecdhPubkeyA.c_str(), ecdhPubkeyA.length(), tmpPub));
		//产生ecdh公私钥对 b
		generate_key_pair_public_private_ecdh_string(ecdhPubkeyB, ecdhPrivateKeyB);
		//协商密钥对比
		printf("\n--------B:pubkey:%s\n", hex2Str((char*)ecdhPubkeyB.c_str(), ecdhPubkeyB.length(), tmpPub));
		test_curve25519_inpu_bindata_agreements((char*)ecdhPubkeyA.c_str(), (char*)ecdhPrivateKeyA.c_str(), (char*)ecdhPubkeyB.c_str(), (char*)ecdhPrivateKeyB.c_str());
		 
	}

		
		
		//initContext();
	//test_curve25519_inputkey_agreements("05fdcb579adbc60ccba1471aa9f91114a3720da3013754b4df0e21ac0224f3b212","e0df8409f502d9077964b6812310040d0852b20255306b4e2c2d3f0067be4654","0527af1839f1f245dc50cbe84814fbc63891ba61037681623b1fb35de00b394d21","70a9c351d39983b08466adfd56e47bbf323a27420b95985fe7b12183c98fec56");
	//destroyContext();


	 


 

return 0;
}
