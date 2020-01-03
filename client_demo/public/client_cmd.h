#ifndef __CLIENT_CMD_H__
#define __CLIENT_CMD_H__

const unsigned int CL_LOGIN_REQ 			= 0x1001;	
const unsigned int CL_LOGIN_RESP 			= 0x1002;

const unsigned int CL_EXIT_REQ				= 0x1003;
const unsigned int CL_EXIT_RESP			= 0x1004;

const unsigned int CL_FORCE_REQ			= 0x1005;
const unsigned int CL_FORCE_RESP       		= 0x1006;	

const unsigned int CL_SEND_MSG_REQ			= 0x1007;
const unsigned int CL_SEND_MSG_RESP     		= 0x1008;	

const unsigned int CL_RECV_MSG_REQ			= 0x1009;
const unsigned int CL_RECV_MSG_RESP     		= 0x1010;
	
const unsigned int CL_SEND_MSG_STATE_REQ		= 0x1011;
const unsigned int CL_SEND_MSG_STATE_RESP		= 0x1012;	

const unsigned int CL_RECV_MSG_STATE_REQ		= 0x1013;
const unsigned int CL_RECV_MSG_STATE_RESP		= 0x1014;	

const unsigned int CL_PUSH_NOTICE_REQ			= 0x1015;
const unsigned int CL_PUSH_NOTICE_RESP			= 0x1016;

const unsigned int CL_ADD_FRIEND_REQ			= 0x1017;
const unsigned int CL_ADD_FRIEND_RESP			= 0x1018;

const unsigned int CL_DO_ADD_FRIEND_REQ		= 0x1021;
const unsigned int CL_DO_ADD_FRIEND_RESP		= 0x1022;

const unsigned int CL_ADD_GROUP_REQ			= 0x1023;
const unsigned int CL_ADD_GROUP_RESP			= 0x1024;

const unsigned int CL_DO_ADD_GROUP_REQ			= 0x1027;
const unsigned int CL_DO_ADD_GROUP_RESP		= 0x1028;

const unsigned int CL_INVITE_ADD_GROUP_REQ		= 0x1029;
const unsigned int CL_INVITE_ADD_GRPUP_RESP		= 0x1030;

const unsigned int CL_DO_INVITE_ADD_GROUP_REQ		= 0x1033;
const unsigned int CL_DO_INVITE_ADD_GROUP_RESP		= 0x1034;

const unsigned int CL_PULL_USER_ONLINE_INFO_REQ	= 0x1035;    
const unsigned int CL_PULL_USER_ONLINE_INFO_RESP	= 0x1036;     

const unsigned int CL_SEND_GROUP_MSG_REQ		= 0x1037;
const unsigned int CL_SEND_GROUP_MSG_RESP		= 0x1038;

const unsigned int CL_RECV_GROUP_MSG_REQ		= 0x1039;
const unsigned int CL_RECV_GROUP_MSG_RESP		= 0x1040;

const unsigned int CL_SEND_GROUP_MSG_STATE_REQ		= 0x1041;
const unsigned int CL_SEND_GROUP_MSG_STATE_RESP	= 0x1042;

const unsigned int CL_RECV_GROUP_MSG_STATE_REQ		= 0x1043;
const unsigned int CL_RECV_GROUP_MSG_STATE_RESP	= 0x1044;

const unsigned int CL_REPORT_NO_READ_SUM_REQ         	= 0x1045;
const unsigned int CL_REPORT_NO_READ_SUM_RESP        	= 0x1046;

const unsigned int CL_SEND_INPUT_STATE_REQ          	= 0x1051;
const unsigned int CL_SEND_INPUT_STATE_RESP          	= 0x1052;

const unsigned int CL_RECV_INPUT_STATE_REQ             = 0x1053;
const unsigned int CL_RECV_INPUT_STATE_RESP            = 0x1054;

const unsigned int CL_BATCH_SEND_MSG_STATE_REQ       	= 0x1055;
const unsigned int CL_BATCH_SEND_MSG_STATE_RESP      	= 0x1056;

const unsigned int CL_REPORT_GROUP_MSG_STATE_REQ       = 0x1059;
const unsigned int CL_REPORT_GROUP_MSG_STATE_RESP      = 0x1060;

const unsigned int CL_BATCH_REPORT_GROUP_MSG_STATE_REQ         = 0x1063;
const unsigned int CL_BATCH_REPORT_GROUP_MSG_STATE_RESP        = 0x1064;

const unsigned int CL_DISMISS_GROUP_REQ = 0x1065;
const unsigned int CL_DISMISS_GROUP_RESP = 0x1066;

const unsigned int CL_PING_REQ				= 0x1101;
const unsigned int CL_PING_RESP			= 0x1102;

#endif//__CL_CMD_H__

