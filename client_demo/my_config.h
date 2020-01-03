#ifndef __MY_CONFIGXX_H__
#define __MY_CONFIGXX_H__

#include <map>
#include <string>
#include<queue>

#include <pthread.h>
#include <signal.h>
#include"LoginAuthTask.h"
using namespace std;
template <class T>
class TQueue 
{
	pthread_mutex_t m_mutex ;
public:
	TQueue()
	{
		pthread_mutex_init(&m_mutex
			, NULL );
		  
	}
	~TQueue()
	{
		pthread_mutex_destroy(&m_mutex);
	}

	void push(T  t) {
		pthread_mutex_lock(&m_mutex);
		m_queueIdle.push(t);
		pthread_mutex_unlock(&m_mutex);
	}
	T  frontPop() {
		T  t ;
		pthread_mutex_lock(&m_mutex);
		 t=m_queueIdle.front();
		 m_queueIdle.pop();
		pthread_mutex_unlock(&m_mutex);
		return t;
	}

	queue<T> m_queueIdle;//空闲人员队列

};
extern TQueue<LoginAuthTask*> g_queueIdle;//空闲人员队列


class CMyConfig
{
public:
	CMyConfig();

	int ReadConfig(const char *root_dir);
	int ReadConfigFile(const char *filename);
	int ReadUserList(const char* path_file);

	string GetValueByKey(const char *key);
	void SetValueByKey(const char *root_dir, const char *key, const char* value);

public:
	map<string, string>	m_map;	
	//Queue<LoginAuthTask*> m_queueUsed;//已经使用队列
	
};

#endif//__MY_CONFIGXX_H__



