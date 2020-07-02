#include "event.h"
Event::Event(void* p, int type):
    handle(p),
    ieventType(type)
{
}

Event::~Event()
{
}

LoginRspEvent::LoginRspEvent(void* p,int type, int status): 
    istatus(status),
    Event(p, type)
{
}

LoginRspEvent::~LoginRspEvent()
{
}