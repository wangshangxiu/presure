
#include"comm.h"
#include"client.h"

#include"my_config.h"
using namespace std;
#define SOCKET_BUF_LEN 1024
// q全局变量
TParam g_cmdParam;
TCount g_count;//统计记录对象
signal_context *global_context;//signal 使用

 

#include "coroutine.h"

void initContext()
{
	int result;
	result = signal_context_create(&global_context, 0);
	//    ck_assert_int_eq(result, 0);
	signal_context_set_log_function(global_context, im_libsignal_log);

	im_setup_crypto_provider(global_context);
}

void  destroyContext()
{
	signal_context_destroy(global_context);
}




//输入两对，公钥私钥（16进制串，公钥前面加了5），测试协商密钥一致性;公钥33字节，66个16进制字符串；私钥32个字节；64个16进制字符串
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


	//16进制转为二进制
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

		//fprintf(stderr, "%s ", prefix);
		uint8_t *data = signal_buffer_data(buffer);
		int len = signal_buffer_len(buffer);
		publicKey.append((const char*)data, len);
		/*int i;
		for (i = 0; i < len; i++) {
			if (i > 0 && (i % 40) == 0) {
				//fprintf(stderr, "\n");
			}
			publicKey.append(data, len);
			fprintf(stderr, "%02X", data[i]);
		}
		fprintf(stderr, "\n");*/
		signal_buffer_free(buffer);

	}
	//pub
	{


		signal_buffer *buffer;
		ec_public_key_serialize(&buffer, alice_public_key);

		 
		uint8_t *data = signal_buffer_data(buffer);
		int len = signal_buffer_len(buffer);

		privateKey.append((const char*)data, len);
		 
		signal_buffer_free(buffer);
	}

	signal_context_destroy(context);

}

//自己生成测试公钥，私钥，协商密码ecdh
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




void showStats()
{
	int count = 0;
	while (true)
	{
		sleep(1);
		count++;
		int nowsend = g_count.sendCount;
		int nowrecv = g_count.recvCount;
		fprintf(stderr, "send avg:%f, recv avg:%f ,qps send:%f,qps recv:%f\n", 1.0*nowsend / count, 1.0* nowrecv / count, 1.0*(nowsend - g_count.lastSendCount), 1.0*(nowrecv - g_count.lastRecvCount));

		g_count.lastRecvCount = nowrecv;
		g_count.lastSendCount = nowsend;

	};

}

//f发送数据到对端
void sendDataWorker(int fd,TFlag*pFlag,LoginAuthTask*pUserTask)
{
	int sockfd = fd;// g_fd;

	
	  int seq = 0;
	  seq = pUserTask->m_seq;
	//bool isExit = false;
	int  iSendRet = 0;// send(sockfd, sendBuf, totalLen, 0);
	int iSendPos = 0;


	while (pFlag->isNormal)
	{
		//usleep(100000);
		seq++;
		short bodyLen = 0;

		char buf[SOCKET_BUF_LEN] = "reqzifuczifuczifuczifuczifuczifuczifuczifuczifuczifuczifuczifuczifuczifuczifuczifuczifuczifucz";
		int len = strlen(buf) + 1;
		bodyLen = len - 1;
		int totalLen = bodyLen + 6;


		// 阻塞的write已被HOOK，等待期间切换执行其他协程。
		char sendBuf[SOCKET_BUF_LEN] = "";

		bodyLen = htons(bodyLen);
		memcpy(sendBuf, &bodyLen, sizeof(bodyLen));
		memcpy(sendBuf + sizeof(bodyLen), &seq, sizeof(seq));
		memcpy(sendBuf + sizeof(bodyLen) + sizeof(seq), buf, len - 1);

		iSendRet = 0;// send(sockfd, sendBuf, totalLen, 0);
		iSendPos = 0;
		while (true)
		{
			iSendRet = send(sockfd, sendBuf + iSendPos, totalLen - iSendPos, 0);
			if (iSendRet <= 0)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				{
					usleep(10000);
					continue;
				}
				else
				{
					//连接出问题，推出socket
					pFlag->isNormal = false;
					break;
				}

			}
			else if (iSendRet == (totalLen - iSendPos))
			{
				g_count.sendCount++;
				break;

			}
			else//yi bu fen
			{
				iSendPos += iSendRet;
				if (iSendPos == totalLen)
					break;

				continue;
			}
		}//while

		 //(void)wn;
		 //        printf("send [%d] %s,seq:%d\n", totalLen, buf,seq);




	}//while


}
void client(char* ip, short sport, LoginAuthTask*pUserTask)
{
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sport);
	addr.sin_addr.s_addr = inet_addr(ip);
	// 阻塞的connect已被HOOK，等待期间切换执行其他协程。
	if (-1 == connect(sockfd, (sockaddr*)&addr, sizeof(addr))) {
		fprintf(stderr, "connect error:%s\n", strerror(errno));
		return;//exit(1);
	}

	TFlag* pFlag = new TFlag() ;
	pFlag->isNormal = false;
	//login request

	//iSendRet = send(sockfd, sendBuf + iSendPos, totalLen - iSendPos, 0);
	//LoginAuthTask tUser;
	string body;
	string pub, pri;
	generate_key_pair_public_private_ecdh_string(pub,pri);
	pUserTask->m_strLocalEcdhPubKey = pub;
	pUserTask->m_strLocalEcdhPriKey = pri;
	pUserTask->makePacket(body);
	string head =pUserTask->makeHead(body);

	head.append(body);
	int iSendRet = send(sockfd, head.c_str(), head.length(), 0);
	pFlag->isExitSendTask = false;
	//g_fd = sockfd;
	pFlag->isNormal = true;
	THead tHead;
	char rcv_buf[SOCKET_BUF_LEN];
	while (pFlag->isNormal)
	{




		static int recvCount = 0;
		// 阻塞的read已被HOOK，等待期间切换执行其他协程。

		memset(&tHead, 0, sizeof(tHead));
		int n = recv(sockfd, &tHead, sizeof(tHead), MSG_PEEK);
		if (n == -1) {
			if (EAGAIN == errno || EINTR == errno || errno == EWOULDBLOCK)
			{
				usleep(1000);
				continue;
			}
			else
			{
				close(sockfd);
				pFlag->isNormal = false;
				break;
				//return;
			}

			fprintf(stderr, "read error:%s\n", strerror(errno));
		}
		else if (n == 0) {
			fprintf(stderr, "read eof\n");
			usleep(1000);
			//	continue;
			pFlag->isNormal = false;
			break;
			//return;
		}
		else {
			// echo
			do {
				string sRecv;
				sRecv = "";
				memset(rcv_buf, 0, sizeof(rcv_buf));
				short iTotalLen = ntohs(tHead.len);
				int ret = recv(sockfd, rcv_buf, iTotalLen, MSG_PEEK);
				if (ret >= iTotalLen)
				{
					int iRet = recv(sockfd, rcv_buf, iTotalLen, 0);
					if (iRet == iTotalLen)
					{


						THead *pHead = (THead*)rcv_buf;
						
						switch (ntohl(pHead->cmd))
						{
						case CL_LOGIN_RESP:
							
							sRecv.append(rcv_buf, iTotalLen);
							pUserTask->unpackLogin(sRecv);
							//if login success
							//登录后启动写
							 
							go[=]{ sendDataWorker(sockfd,pFlag ,pUserTask); };
							break;
						case CL_PING_RESP://心跳

							break;


						}
						
						g_count.recvCount++;
						//fprintf(stderr, "read buf:%d:%s\n", iTotalLen,rcv_buf+6);
						recvCount++;
						break;

					}
					else
					{
						close(sockfd);
						pFlag->isNormal = false;
						break;
						//return;
					}
				}
				else
				{
					break;
				}
			} while (true);

			//printf("recv [%d] %s\n", n, rcv_buf);
		}
	}//while
	//wait exit
	for (;;)
	{
		if (pFlag->isExitSendTask)
			break;
		else
			sleep(1);
	}
	g_count.connectTotal--;
	g_queueIdle.push(pUserTask);

}

/*int main(int argc, char* argv[])
{
	//test_curve25519_random_agreements();
	initContext();
	test_curve25519_inputkey_agreements("05fdcb579adbc60ccba1471aa9f91114a3720da3013754b4df0e21ac0224f3b212", "e0df8409f502d9077964b6812310040d0852b20255306b4e2c2d3f0067be4654", "0527af1839f1f245dc50cbe84814fbc63891ba61037681623b1fb35de00b394d21", "70a9c351d39983b08466adfd56e47bbf323a27420b95985fe7b12183c98fec56");
	destroyContext();




	//parse input cmd 
	//-a:测试类别：1登录，2 登录发消息 

	//-c 多少并发连接
	//-s 每个连接每秒发送多少次
	//-n 总共发送多少
	//-t 运行时间，秒
	//-b -e ： b开始用户id -e 结束用户id  如userid： 1000~2000之间用户id
	string usage = "";
	printf("Usage:\n");
	printf("-i server ip\n");
	printf("-p server port\n");
	printf("-a 业务类别\n");
	printf("-c 多少并发连接\n");
	printf("-s 每个连接每秒发送多少次\n");
	printf("-n 总共发送多少\n");
	printf("-t 运行时间，秒\n");
	printf("-d 线程数，秒\n");
	printf("-b -e ： b开始用户id -e 结束用户id  如userid： 1000~2000之间用户id\n");
	int opt;
	char *pstring = "a:c:s:t:n:b:e:d:i:p:";
	//if(argc <2)
	while ((opt = getopt(argc, argv, pstring)) != -1)
	{
		printf("opt = %c\t\t", opt);
		printf("optarg = %s\t\t", optarg);
		//printf("optind = %d\t\t", optind);
		//printf("argv[optind] = %s\n", argv[optind]);
		switch (opt)
		{
		case 'i':
		{
			g_cmdParam.iIP = (optarg);
			break;
		}
		case 'p':
		{
			g_cmdParam.pPort = atoi(optarg);
			break;
		}
		case 'a':
		{
			g_cmdParam.aTestType = atol(optarg);
			break;
		}
		case 'c':
		{
			g_cmdParam.cConcurrentNumber = atol(optarg);
			break;
		}
		case 'n':
		{
			g_cmdParam.nTotalNumber = atol(optarg);
			break;
		}
		case 't':
		{
			g_cmdParam.tStopTime = time(NULL) + atol(optarg);
			break;
		}
		case 's':
		{
			g_cmdParam.sQps = atol(optarg);
			break;
		}
		case 'b':
		{
			g_cmdParam.bStartUserId = atol(optarg);
			break;
		}
		case 'e':
		{
			g_cmdParam.eEndUserId = atol(optarg);
			break;
		}
		case 'd':
		{
			g_cmdParam.dThreadNumber = atol(optarg);
			break;
		}



		default:
		{
			printf("input root dir: \n");
			break;
		}
		}
	}//while


	 //
	for (int i = 0; i<g_cmdParam.cConcurrentNumber; i++)
		go[=]{ client((char*)g_cmdParam.iIP.c_str(),g_cmdParam.pPort); };
	//统计
	go showStats;

	//q启动线程
	{
		boost::progress_timer pt;
		boost::thread_group tg;
		for (int i = 0; i < g_cmdParam.dThreadNumber; ++i)
		{
			tg.create_thread([] {
				uint32_t c = 0;
				while (!g_Scheduler.IsEmpty()) {
					c += g_Scheduler.Run();
				}
				printf("[%lu] do count: %u\n", pthread_self(), c);
			});
		}
		tg.join_all();
		 
	}



	return 0;
}
*/
