#ifndef _UVCONN_H
#define _UVCONN_H
#include <uv.h>
#include <map>
#include "CircleBuffer.hpp"
#include "atomic_ops.h"
#include "ring_buffer.h"
#include "comm.h"
namespace uvconn
{
extern void *p_recv_mem;                     //writer:sockect线程；reader:业务线程  
extern RingBuffer rb_recv;              //存放接收到的业务pack的lock-free缓冲
extern std::vector<void*> p_send_mem;                          //writer:业务线程, reader:sockect线程
extern std::vector<RingBuffer*> rb_send;                       //(RB_SIZE, false, false),多线程处理业务后要发包入缓冲，通知socket线程发送,有几个业务线程就有几个这样的
extern std::map<uv_tcp_t*, void*> g_mapConnCache; //socket映射连接，连接与缓冲区关联，目的是不去占用uv_tcp_t.data

void on_connect(uv_connect_t* req, int status);
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void echo_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void on_parse_pack(const uv_stream_t* stream);
void close_cb(uv_handle_t* handle);
void write_cb(uv_write_t* req, int status);
void uv_async_call(uv_async_t* handle);

void uv_personal_heatBeat_timer_callback(uv_timer_t* handle);
void uv_msg_timer_callback(uv_timer_t* handle);
};

#endif//_UVCONN_H