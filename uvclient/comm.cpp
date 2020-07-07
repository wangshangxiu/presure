#include "comm.h"
#include <chrono>
long long GetMicrosecond()
{
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}