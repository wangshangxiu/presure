1、CircleBuffer.hpp用作socket的应用缓冲区
2、ring_buffer.h ring_buffer.cpp, atomic_ops.h 用于业务线程和主线程通讯，存放的是收发的业务包
3、test.cpp是测试用例，用于测试CircleBuffer, ring_buffer.cpp
