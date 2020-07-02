
#include "logger.h"
#include "proctitle_helper.h"
std::mutex Logger::m_mutex;
Logger* Logger::m_logger = nullptr;
Logger::Logger()
{
}

Logger::~Logger()
{
}

Logger* Logger::GetInstance()
{
    if(m_logger == nullptr)
    {
        std::lock_guard<std::mutex> mtx(m_mutex);
        if(m_logger == nullptr)
        {
            m_logger = new Logger();
        }
    }
    return m_logger;
}

bool Logger::InitLogger(const util::CJsonObject& oJsonConf)
{
    if (m_bInitLogger)  // 已经被初始化过，只修改日志级别
    {
        int iLogLevel = 0;
        if (oJsonConf.Get("log_level", iLogLevel))
        {
        	m_oLogger.setLogLevel(iLogLevel);
        }
        return(true);
    }
    else
    {
        int iMaxLogFileSize = 0;
        int iMaxLogFileNum = 0;
        int iLogLevel = 0;
        int iLoggingPort = 9000;
        std::string strLoggingHost;
        std::string strLogname = oJsonConf("log_path") + std::string("/") + getproctitle() + std::string(".log");
        std::string strParttern = "[%D,%d{%q}][%t][%p][%l] %m%n";
#if 0        
        std::ostringstream ssServerName;
        ssServerName << strServername;
#endif     
        iLogLevel = log4cplus::INFO_LOG_LEVEL;
		if (oJsonConf.Get("log_level", iLogLevel))
		{
			switch (iLogLevel)
			{
				case log4cplus::DEBUG_LOG_LEVEL:
				case log4cplus::INFO_LOG_LEVEL:
				case log4cplus::TRACE_LOG_LEVEL:
				case log4cplus::WARN_LOG_LEVEL:
				case log4cplus::ERROR_LOG_LEVEL:
				case log4cplus::FATAL_LOG_LEVEL:
					break;
				default:
					iLogLevel = log4cplus::INFO_LOG_LEVEL;
			}
		}
        oJsonConf.Get("max_log_file_size", iMaxLogFileSize);
        oJsonConf.Get("max_log_file_num", iMaxLogFileNum);
        log4cplus::initialize();
        log4cplus::SharedAppenderPtr file_append(new log4cplus::RollingFileAppender(strLogname, iMaxLogFileSize, iMaxLogFileNum));
        file_append->setName(strLogname);
        std::auto_ptr<log4cplus::Layout> layout(new log4cplus::PatternLayout(strParttern));
        file_append->setLayout(layout);
        //log4cplus::Logger::getRoot().addAppender(file_append);
        m_oLogger = log4cplus::Logger::getInstance(strLogname);
        m_oLogger.setLogLevel(iLogLevel);
        m_oLogger.addAppender(file_append);
#if 0
        if (oJsonConf.Get("socket_logging_host", strLoggingHost) && oJsonConf.Get("socket_logging_port", iLoggingPort))
        {
            log4cplus::SharedAppenderPtr socket_append(new log4cplus::SocketAppender(strLoggingHost, iLoggingPort, ssServerName.str()));
            socket_append->setName(ssServerName.str());
            socket_append->setLayout(layout);
            socket_append->setThreshold(log4cplus::INFO_LOG_LEVEL);
            m_oLogger.addAppender(socket_append);
        }
#endif
        m_bInitLogger = true;
        return(true);
    }
}
