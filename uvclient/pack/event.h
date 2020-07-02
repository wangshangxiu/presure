#ifndef _EVENT_H
#define _EVENT_H
class Event
{
public:
    int ieventType = EVENT_DEFAULT;
    void *handle = nullptr;
public:
    enum {
        EVENT_DEFAULT,
        EVENT_LOGIN_SUCCESSE,
        EVENT_LOGIN_FAILED,
    };
    Event(void* p, int type );
    ~Event();
};

class LoginRspEvent :public Event
{
public:
    int istatus = 0;
public:
    LoginRspEvent(void* p, int type, int status);
    ~LoginRspEvent();
};




#endif //_EVENT_H