#ifndef _EVENT_H
#define _EVENT_H
class Event
{
public:
    int ieventType;
    void *handle;
public:
    enum {
        EVENT_DEFAULT,
        EVENT_LOGIN_SUCCESSE,
        EVENT_LOGIN_FAILED,
    };
    Event(void* p = nullptr, int type = EVENT_DEFAULT);
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