#!/usr/bin/bash
echo "grep -Hrn 'close callback' log/presureClient_* | wc -l"
grep -Hrn "close callback" log/presureClient_* | wc -l
 echo "netstat -tlnap | grep 27010 | wc -l"
 netstat -tlnap | grep 27010 | wc -l


 echo "grep -Hrn 'current enstablished connets nums' log/presureClient_* |wc -l"
 grep -Hrn "current enstablished connets nums" log/presureClient_* |wc -l
 echo "grep -Hrn 'errorName' log/presureClient_*   | wc -l"
 grep -Hrn "errorName" log/presureClient_*   | wc -l


echo "grep -Hrn 'Start sendMsg on stream' log/presureClient_* | wc -l"
grep -Hrn "Start sendMsg on stream" log/presureClient_* | wc -l
echo  "grep -Hrn 'End sendMsg on stream' log/presureClient_* | wc -l"
grep -Hrn "End sendMsg on stream" log/presureClient_* | wc -l
echo "grep -Hrn 'call uv_write error' log/presureClient_* | wc -l"
grep -Hrn "call uv_write error" log/presureClient_* | wc -l


 echo "grep -Hrn 'Login at' log/presureClient_* | wc -l"
 grep -Hrn "Login at" log/presureClient_* | wc -l
 echo "grep -Hrn 'Login at' log/presureClient_* | grep status\(0\) | wc -l"
 grep -Hrn "Login at" log/presureClient_* | grep status\(0\) | wc -l
 echo "grep -Hrn 'Login at' log/presureClient_* | grep -v status\(0\) | wc -l"
 grep -Hrn "Login at" log/presureClient_* | grep -v status\(0\) | wc -l


echo "grep -Hrn 'drop pack cmd' log/presureClient_* | wc -l"
grep -Hrn "drop pack cmd" log/presureClient_* | wc -l


 echo "grep -Hrn 'uv_logintask_statistics_timer completed' log/presureClient_*   | wc -l"
 grep -Hrn "uv_logintask_statistics_timer completed" log/presureClient_*   | wc -l
 echo "grep -Hrn 'uv_logintask_statistics_timer completed' log/presureClient_*"
 grep -Hrn "uv_logintask_statistics_timer completed" log/presureClient_*

 
 echo "grep -Hrn 'alloc_buffer' log/presureClient_*   | wc -l"
 grep -Hrn "alloc_buffer" log/presureClient_*   | wc -l

 #echo "grep -Hrn 'Login Tps (QPS' log/presureClient_*  |wc -l"
 #grep -Hrn "Login Tps (QPS" log/presureClient_*  |wc -l

  #echo "grep -Hrn 'Login Tps (QPS' log/presureClient_*"
  #grep -Hrn "Login Tps (QPS" log/presureClient_*



