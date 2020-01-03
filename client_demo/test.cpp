#include"client.h"

 

CMyConfig g_cfg;
#include "coroutine.h"
int main(int argc, char* argv[])
{
	//test_curve25519_random_agreements();
	//initContext();
	//test_curve25519_inputkey_agreements("05fdcb579adbc60ccba1471aa9f91114a3720da3013754b4df0e21ac0224f3b212","e0df8409f502d9077964b6812310040d0852b20255306b4e2c2d3f0067be4654","0527af1839f1f245dc50cbe84814fbc63891ba61037681623b1fb35de00b394d21","70a9c351d39983b08466adfd56e47bbf323a27420b95985fe7b12183c98fec56");
	///destroyContext();


	g_cfg.ReadConfig("./conf/client.conf");
	RSA * pubKey =readRsaPublicKeyFromFile("./conf/rsa_public_key_2048.pem");
	LoginAuthTask::setRsaPublickKey(pubKey);


	//获取用户
	g_cfg.ReadUserList("./conf/user.conf");
 
	 


	//string sRsa =g_cfg.GetValueByKey("rsa_public_key");

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
				g_cmdParam.tStopTime = time(NULL)+atol(optarg);
				break;
			}
			case 's':
			{
				g_cmdParam.sQps = atol(optarg);
				break;
			}
			case 'b':
			{
				g_cmdParam.bStartUserId =   atol(optarg);
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

 
	//维持连接
	go[=]{ 
			for (int i = 0; i < g_cmdParam.cConcurrentNumber; i++)
			{
				LoginAuthTask *pUserTask = NULL;
				if (g_count.connectTotal < g_cmdParam.cConcurrentNumber)
				{
					 pUserTask = g_queueIdle.frontPop();
					 

					g_count.connectTotal++;
				}
				else
				{
					sleep(1);
					continue;
				}
				go[=]{ client((char*)g_cmdParam.iIP.c_str(),g_cmdParam.pPort,pUserTask); };
			};
	  };
	//统计
	go showStats;

	//启动线程
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
		//printf("%d threads, run %d coroutines, %d times switch. cost ",
		//	thread_count, co_count, co_count * switch_per_co);
	}



return 0;
}
