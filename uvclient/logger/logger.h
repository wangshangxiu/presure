#ifndef _LOGGER_H
#define _LOGGER_H
#include <string>
#include <mutex>
#include "log4cplus/logger.h"
#include "log4cplus/fileappender.h"
#include "log4cplus/loggingmacros.h"
#include "CJsonObject.hpp"
class Logger
{
public:
    bool InitLogger(const util::CJsonObject& oJsonConf); 
    static Logger* GetInstance();
    log4cplus::Logger GetLogger(){return(m_oLogger);}
private:
    Logger();
    ~Logger();
private:
    static std::mutex m_mutex;
    static Logger* m_logger;
    bool m_bInitLogger = false; 
    log4cplus::Logger m_oLogger;
};



#endif//_LOGGER_H
