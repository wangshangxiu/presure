
#include"comm.h"
#include"client.h"
#include <string.h>
using namespace std;
#define SOCKET_BUF_LEN 1024
 
signal_context *global_context;//signal ʹ��
void initContext()
{
	int result;
	result = signal_context_create(&global_context, 0);
	//    ck_assert_int_eq(result, 0);
	signal_context_set_log_function(global_context, test_log);

	setup_test_crypto_provider(global_context);
}

void  destroyContext()
{
	signal_context_destroy(global_context);
}



//da��ӡ˽Կ
void print_private_key(const char *prefix, ec_private_key *key)
{
	signal_buffer *buffer;
	ec_private_key_serialize(&buffer, key);

	fprintf(stderr, "%s ", prefix);
	uint8_t *data = signal_buffer_data(buffer);
	int len = signal_buffer_len(buffer);
	int i;
	for (i = 0; i < len; i++) {
		if (i > 0 && (i % 40) == 0) {
			fprintf(stderr, "\n");
		}
		fprintf(stderr, "%02X", data[i]);
	}
	fprintf(stderr, "\n");
	signal_buffer_free(buffer);
}
//�������ԣ���Կ˽Կ��16���ƴ�����Կǰ�����5��������Э����Կһ����;��Կ 66��16�����ַ�����˽Կ 64��16�����ַ���
void test_curve25519_inputkey_agreements(char* alicePubKey, char* alicePriKey, char*bobPubKey, char* bobPriKey)
{
	const int  KEY_LEN = 32;
	int result;

	uint8_t alicePublic[KEY_LEN + 1] = { 0 };

	uint8_t alicePrivate[KEY_LEN] = { 0 };

	uint8_t bobPublic[KEY_LEN + 1] = { 0 };

	uint8_t bobPrivate[KEY_LEN] = { 0 };

	uint8_t shared[] = { 0 };

	ec_public_key *alice_public_key = 0;
	ec_private_key *alice_private_key = 0;
	ec_public_key *bob_public_key = 0;
	ec_private_key *bob_private_key = 0;
	uint8_t *shared_one = 0;
	uint8_t *shared_two = 0;


	//16����תΪ������
	hexStrToByte((char*)alicePubKey, KEY_LEN * 2 + 2, (unsigned char*)alicePublic);
	hexStrToByte((char*)alicePriKey, KEY_LEN * 2, (unsigned char*)alicePrivate);

	hexStrToByte((char*)bobPubKey, KEY_LEN * 2 + 2, (unsigned char*)bobPublic);
	hexStrToByte((char*)bobPriKey, KEY_LEN * 2, (unsigned char*)bobPrivate);




	/* Initialize Alice's public key */
	result = curve_decode_point(&alice_public_key, alicePublic, sizeof(alicePublic), global_context);


	/* Initialize Alice's private key */
	result = curve_decode_private_point(&alice_private_key, alicePrivate, sizeof(alicePrivate), global_context);


	/* Initialize Bob's public key */
	result = curve_decode_point(&bob_public_key, bobPublic, sizeof(bobPublic), global_context);

	/* Initialize Bob's private key */
	result = curve_decode_private_point(&bob_private_key, bobPrivate, sizeof(bobPrivate), global_context);


	/* Calculate key agreement one */
	result = curve_calculate_agreement(&shared_one, alice_public_key, bob_private_key);


	/* Calculate key agreement two */
	result = curve_calculate_agreement(&shared_two, bob_public_key, alice_private_key);


	/* Assert that key agreements are correct */

	if (memcmp(shared_one, shared_two, 32) == 0)
	{
		printf("share key is equal \n");
		char tmp[65] = "";
		printf("sharekey:%s", hex2Str((char*)shared_one, 32, (char*)tmp));
	}
	else
	{
		printf("share key is no equal!\n");
	}


	/* Cleanup */
	if (shared_one) { free(shared_one); }
	if (shared_two) { free(shared_two); }
	SIGNAL_UNREF(alice_public_key);
	SIGNAL_UNREF(alice_private_key);
	SIGNAL_UNREF(bob_public_key);
	SIGNAL_UNREF(bob_private_key);




}
//����һ��ecdh ��˽Կ��32���ֽ�

void generate_key_pair_public_private_ecdh_string(string& publicKey, string &privateKey)
{

	signal_context *context;
	signal_context_create(&context, 0);
	setup_test_crypto_provider(context);

	ec_key_pair *alice_key_pair = 0;
	ec_public_key *alice_public_key = 0;
	ec_private_key *alice_private_key = 0;
	int result = curve_generate_key_pair(context, &alice_key_pair);
	//ck_assert_int_eq(result, 0);
	alice_public_key = ec_key_pair_get_public(alice_key_pair);
	alice_private_key = ec_key_pair_get_private(alice_key_pair);



	//private
	{
		signal_buffer *buffer;
		ec_private_key_serialize(&buffer, alice_private_key);
 
		uint8_t *data = signal_buffer_data(buffer);
		int len = signal_buffer_len(buffer);
		
		privateKey.append((const char*)data, len);
 
		signal_buffer_free(buffer);

	}
	//pub
	{


		signal_buffer *buffer;
		ec_public_key_serialize(&buffer, alice_public_key);

		 
		uint8_t *data = signal_buffer_data(buffer);
		int len = signal_buffer_len(buffer);
 
		publicKey.append((const char*)data, len);
		 
		signal_buffer_free(buffer);
	}

	signal_context_destroy(context);

}


// �������ԣ���Կ˽Կ��16���ƴ�����Կǰ�����5��������Э����Կһ����; ��Կ33�ֽ� ��˽Կ32���ֽ� 
void test_curve25519_inpu_bindata_agreements(char* alicePubKey, char* alicePriKey, char*bobPubKey, char* bobPriKey)
{
	const int  KEY_LEN = 32;
	int result;

	uint8_t alicePublic[KEY_LEN + 1] = { 0 };

	uint8_t alicePrivate[KEY_LEN] = { 0 };

	uint8_t bobPublic[KEY_LEN + 1] = { 0 };

	uint8_t bobPrivate[KEY_LEN] = { 0 };

	uint8_t shared[] = { 0 };

	ec_public_key *alice_public_key = 0;
	ec_private_key *alice_private_key = 0;
	ec_public_key *bob_public_key = 0;
	ec_private_key *bob_private_key = 0;
	uint8_t *shared_one = 0;
	uint8_t *shared_two = 0;


	signal_context *context;
	signal_context_create(&context, 0);
	setup_test_crypto_provider(context);


	//16����תΪ������
	memcpy(alicePublic, alicePubKey, KEY_LEN + 1);
	memcpy(alicePrivate, alicePriKey, KEY_LEN );
 
	memcpy(bobPublic, bobPubKey, KEY_LEN + 1);
	memcpy(bobPrivate, bobPriKey, KEY_LEN );

	 


	/* Initialize Alice's public key */
	result = curve_decode_point(&alice_public_key, alicePublic, sizeof(alicePublic),  context);


	/* Initialize Alice's private key */
	result = curve_decode_private_point(&alice_private_key, alicePrivate, sizeof(alicePrivate), context);


	/* Initialize Bob's public key */
	result = curve_decode_point(&bob_public_key, bobPublic, sizeof(bobPublic), context);

	/* Initialize Bob's private key */
	result = curve_decode_private_point(&bob_private_key, bobPrivate, sizeof(bobPrivate), context);


	/* Calculate key agreement one */
	result = curve_calculate_agreement(&shared_one, alice_public_key, bob_private_key);


	/* Calculate key agreement two */
	result = curve_calculate_agreement(&shared_two, bob_public_key, alice_private_key);


	/* Assert that key agreements are correct */

	if (memcmp(shared_one, shared_two, 32) == 0)
	{
		printf("share key is equal \n");
		char tmp[67] = "";
		printf("sharekey:%s", hex2Str((char*)shared_one, 32, (char*)tmp));
	}
	else
	{
		printf("share key is no equal!\n");
	}


	/* Cleanup */
	if (shared_one) { free(shared_one); }
	if (shared_two) { free(shared_two); }
	SIGNAL_UNREF(alice_public_key);
	SIGNAL_UNREF(alice_private_key);
	SIGNAL_UNREF(bob_public_key);
	SIGNAL_UNREF(bob_private_key);

 
	signal_context_destroy(context);


}
uint8_t* calculate_ecdh_share_key(const char* alicePubKey, const char* alicePriKey)
{
	const int  KEY_LEN = 32;

	uint8_t alicePublic[KEY_LEN + 1] = { 0 };
	uint8_t alicePrivate[KEY_LEN] = { 0 };
	ec_public_key *alice_public_key = 0;
	ec_private_key *alice_private_key = 0;
	uint8_t *shared_one = 0;



	signal_context *context;
	signal_context_create(&context, 0);
	setup_test_crypto_provider(context);
	memcpy(alicePublic, alicePubKey, KEY_LEN + 1);
	memcpy(alicePrivate, alicePriKey, KEY_LEN );



	/* Initialize Alice's public key */
	curve_decode_point(&alice_public_key, alicePublic, sizeof(alicePublic),  context);
	/* Initialize Alice's private key */
	curve_decode_private_point(&alice_private_key, alicePrivate, sizeof(alicePrivate), context);
	/* Calculate key agreement one */
	curve_calculate_agreement(&shared_one, alice_public_key, alice_private_key);
	/* Assert that key agreements are correct */

	//if (memcmp(shared_one, shared_two, 32) == 0)
	// {
	// 	printf("share key is equal \n");
	// 	char tmp[67] = "";
	// 	printf("sharekey:%s", hex2Str((char*)shared_one, 32, (char*)tmp));
	// }
	// else
	// {
	// 	printf("share key is no equal!\n");
	// }


		/* Cleanup */
	SIGNAL_UNREF(alice_public_key);
	SIGNAL_UNREF(alice_private_key);
	signal_context_destroy(context);

	return shared_one;

}
//�Լ����ɲ��Թ�Կ��˽Կ��Э������ecdh
void test_curve25519_random_agreements()
{
	int result;
	int i;

	ec_key_pair *alice_key_pair = 0;
	ec_public_key *alice_public_key = 0;
	ec_private_key *alice_private_key = 0;
	ec_key_pair *bob_key_pair = 0;
	ec_public_key *bob_public_key = 0;
	ec_private_key *bob_private_key = 0;
	uint8_t *shared_alice = 0;
	uint8_t *shared_bob = 0;

	signal_context *context;
	signal_context_create(&context, 0);
	setup_test_crypto_provider(context);

	//for (i = 0; i < 1; i++) 
	{
		/* Generate Alice's key pair */
		result = curve_generate_key_pair(context, &alice_key_pair);
		//ck_assert_int_eq(result, 0);
		alice_public_key = ec_key_pair_get_public(alice_key_pair);
		alice_private_key = ec_key_pair_get_private(alice_key_pair);
		//ck_assert_ptr_ne(alice_public_key, 0);
		//ck_assert_ptr_ne(alice_private_key, 0);
		{
			print_private_key("alice privatekey:", alice_private_key);
			print_public_key("alice   publickey:", alice_public_key);

		}

		/* Generate Bob's key pair */
		result = curve_generate_key_pair(context, &bob_key_pair);
		//ck_assert_int_eq(result, 0);
		bob_public_key = ec_key_pair_get_public(bob_key_pair);
		bob_private_key = ec_key_pair_get_private(bob_key_pair);
		{
			print_private_key("bob privatekey:", bob_private_key);
			print_public_key("bob   publickey:", bob_public_key);
			//printf("alice publickey :privatekey:%s\n%s\n", hex2Str(bob_public_key->data, 32, szAPubKey), hex2Str(bob_private_key->data, 32, szAPriKey));

		}
		//ck_assert_ptr_ne(bob_public_key, 0);
		//ck_assert_ptr_ne(bob_private_key, 0);

		/* Calculate Alice's key agreement */
		result = curve_calculate_agreement(&shared_alice, bob_public_key, alice_private_key);
		//ck_assert_int_eq(result, 32);
		//ck_assert_ptr_ne(shared_alice, 0);

		/* Calculate Bob's key agreement */
		result = curve_calculate_agreement(&shared_bob, alice_public_key, bob_private_key);
		//ck_assert_int_eq(result, 32);
		//ck_assert_ptr_ne(shared_bob, 0);{
		{
			char szAPubKey[65] = "";
			char szAPriKey[65] = "";
			printf("alice sharekey :bob sharekey:%s\n%s\n", hex2Str((char*)shared_alice, 32, (char*)szAPubKey), hex2Str((char*)shared_bob, 32, (char*)szAPriKey));
		}

		/* Assert that key agreements match */
		if (memcmp(shared_alice, shared_bob, 32) == 0)
		{
			printf("share key is ==\n");
		}
		else
		{
			printf("share key is no equal!\n");
		}

		/* Cleanup */
		if (shared_alice) { free(shared_alice); }
		if (shared_bob) { free(shared_bob); }
		SIGNAL_UNREF(alice_key_pair);
		SIGNAL_UNREF(bob_key_pair);
		alice_key_pair = 0;
		bob_key_pair = 0;
		alice_public_key = 0;
		alice_private_key = 0;
		bob_public_key = 0;
		bob_private_key = 0;
		shared_alice = 0;
		shared_bob = 0;
	}

	signal_context_destroy(context);
}



 