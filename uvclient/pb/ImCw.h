/*******************************************************************************
* Project:  proto
* @file     ImCw.h
* @brief    IM业务命令字定义
* @author   Tommy
* @date:    2019年10月12日
* @note
* Modify history:
******************************************************************************/
#ifndef SRC_IMCW_H_
#define SRC_IMCW_H_

namespace im
{

/**
 * @brief IM业务命令字定义
 * @note IM业务命令字成对出现，从1001开始编号，并且遵从奇数表示请求命令字，
 * 偶数表示应答命令字，应答命令字 = 请求命令字 + 1
 */
enum E_IM_CW
{
	CMD_UNDEFINE                        = 0,        ///< 未定义
	CMD_REQ_SYS_ERROR					= 999,		///< 系统错误请求（无意义，不会被使用）
	CMD_RSQ_SYS_ERROR					= 1000,		///< 系统错误响应

	// 用户相关命令字，如用户注册、用户登录、修改用户资料等，号段：1001~2000
	CMD_REQ_USER_LOGIN                  = 1001,     ///< 用户登录请求
	CMD_RSP_USER_LOGIN                  = 1002,     ///< 用户登录应答
    CMD_REQ_USER_LOGOUT                 = 1003,     ///< 用户退出请求
    CMD_RSP_USER_LOGOUT                 = 1004,     ///< 
//    CMD_RSP_USER_KICED_OFFLINE          = 1005,     ///< 用户被迫下线通知


	CMD_REQ_USER_BEAT            	    = 1101,     ///< 用户心跳
	CMD_RSP_USER_BEAT               	= 1102,     ///<

	CMD_REQ_USER_DISCONNECT             = 1103,     ///< 用户断开连接
	CMD_RSP_USER_DISCONNECT             = 1104, ///<

	CMD_REQ_USER_STATUS_NOTICE		    = 1105,     ///< 用户状态通知
	CMD_RSP_USER_STATUS_NOTICE          = 1106, ///<


	// 用户关系命令字，如关注、取消关注、添加好友、删除好友、拉黑、举报等，号段：2001~3000

	


	// 群管理命令字，如申请入群、退群、踢人、邀请加群等，号段：3001~4000


	// 聊天相关命令字，如单聊、群聊、屏蔽消息等，号段：4001~5000
	CMD_REQ_P2P_MSG_SEND		        = 4001,     ///< 发送单聊消息
	CMD_RSP_P2P_MSG_SEND_ACK	        = 4002,     ///< 发送单聊应答
	// CMD_REQ_P2P_MSG_RECV		        = 4003,     ///< 接收单聊消息
	// CMD_RSP_P2P_MSG_RECV_ACK	        = 4004,     ///< 接收单聊应答
    CMD_REQ_DELIVER_MSGCHAT             = 4003,    ///< 单聊派发请求 SendMsgReq（4001， 4003共用结构体）
	CMD_RSP_DELIVER_MSGCHAT             = 4004,    ///< 单聊派发响应 RecvMsgResp
    CMD_REQ_DELIVER_STATEMSG            = 4007,    ///< 修改单聊状态请求 SendMsgStateReq（4005， 4007共用结构体）
	CMD_RSP_DELIVER_STATEMSG            = 4008,    ///< 修改单聊状态响应 SendMsgStateResp(4008)


	CMD_REQ_SEND_INPUT_STATE            = 4013,    ///< 发送输入状态APP->TS
	CMD_RSP_SEND_INPUT_STATE            = 4014,    ///<发送输入状态APP->TS 响应

	CMD_REQ_RECV_INPUT_STATE            = 4015,    ///< 接收输入状态APP->TS
	CMD_RSP_RECV_INPUT_STATE            = 4016,    ///<接收输入状态APP->TS 响应

    CMD_REQ_DELIVER_BATCHMSG_STATE      = 4019,    ///< 批量修改单聊状态请求 batchSendMsgStateReq（4017， 4019共用结构体）
	CMD_RSP_DELIVER_BATCHMSG_STATE      = 4020,    ///< 批量修改单聊状态响应 batchSendMsgStateResp(4020)

	CMD_REQ_PUSH_USER_ONLINE      = 4021,    ///< 推送在线状态请求TS ->APP
	CMD_RSP_PUSH_USER_ONLINE      = 4022,    ///<

	CMD_REQ_SEND_SUBCRIBE_USER            = 4023,    ///< 订阅用户数据
	CMD_RSP_SEND_SUBCRIBE_USER            = 4024,    ///< 订阅用户数据响应

	CMD_REQ_PUSH_SUBCRIBE_USER            = 4025,    ///< 推送用户订阅
	CMD_RSP_PUSH_SUBCRIBE_USER            = 4026,    ///< 推送用户订阅响应 PushNoticeResp


	CMD_REQ_PULL_USER_ONLINE		    = 4035,     ///< 拉取在线状态请求APP->TS
	CMD_RSP_PULL_USER_ONLINE		    = 4036,     ///< 拉取在线状态应答APP->TS 响应

	CMD_REQ_PUSH_NOTICE_P2P_MSG            = 4037,    ///< 推送单聊通知
	CMD_RSP_PUSH_NOTICE_P2P_MSG            = 4038,    ///< 推送单聊通知响应

	//群，号段：4500~4999

	CMD_REQ_DELIVER_GROUPCHAT			= 4503,		///< 群聊发送命令字(4501, 4053共用结构体)
	CMD_RSP_DELIVER_GROUPCHAT			= 4504,		///< 群聊发送回复

	CMD_REQ_GROUPCHAT_STATE				= 4519,		///< 群状态消息发送命令字(4517， 4519公用结构体)
	CMD_RSP_GROUPCHAT_STATE				= 4520,		///< 群状态消息回复

	CMD_REQ_PUSH_NOTICE_GROUP            = 4525,    ///< 推送群通知
	CMD_RSP_PUSH_NOTICE_GROUP            = 4526,    ///< 推送群通知响应

	CMD_REQ_SEND_SUBCRIBE_GROUP            = 4521,    ///< 订阅群数据
	CMD_RSP_SEND_SUBCRIBE_GROUP            = 4522,    ///< 订阅群数据响应

	CMD_REQ_PUSH_SUBCRIBE_GROUP            = 4523,    ///< 订阅数据推送
	CMD_RSP_PUSH_SUBCRIBE_GROUP            = 4524,    ///< 推送群通知响应

	CMD_REQ_DELIVER_NOTICE_GROUPCHAT	= 4527,		///< 系统通知的群聊消息
	CMD_RSP_DELIVER_NOTICE_GROUPCHAT	= 4528,		///< 系统通知的群聊消息回复

	CMD_REQ_PULL_GROUP_ONLINE		    = 4529,     ///< 拉取群在线状态请求APP->TS
	CMD_RSP_PULL_GROUP_ONLINE		    = 4530,     ///< 拉取群在线状态应答APP->TS 响应

	CMD_REQ_FORCE_EXIT            		= 5005,    ///< 发送下线（封号/踢下线）TS->APP
	CMD_RSP_FORCE_EXIT           		= 5006,    ///<发送下线（封号/踢下线）TS->APP 响应

	CMD_REQ_PUSH_NOTICE                 = 7001,    ///< 推送通知 PushNoticeReq
	CMD_RSP_PUSH_NOTICE                 = 7002,    ///< 推送通知响应 PushNoticeResp

	CMD_REQ_PUSH_LIST_MICRO_SERVICE     = 7103,    ///< 推送通知列表到微服务
	CMD_RSP_PUSH_LIST_MICRO_SERVICE     = 7104,    ///< 推送通知列表到微服务响应

    // IM管理相关命令字，如禁言、禁止登录、封号等，号段：5001~6000

    // 社交相关命令字，如分享、发表说说、评论、回复评论、点赞等，号段：6001~7000


	//用户和群的地理信息等，号段：8001~9000

    //敏感词

};

}   // end of namespace im

#endif /* SRC_IMCW_H_ */
