cmake_minimum_required(VERSION 2.6)
PROJECT(presureClient)

SET(EXECUTABLE_OUTPUT_PATH  ../)
SET(ENCRYPT_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/encrypt)
SET(PB_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/pb)
SET(PACK_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/pack)
SET(BUFFER_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/buffer)
SET(JSON_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/json)
SET(LOGGER_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/logger)
SET(UNIX_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/unix)

#if(APPLE)
#    SET(PB_LIB_DIR ../base/pb/lib/mac)
#    SET(SECURITY_LIB_DIR ../base/security/lib/mac)
#elseif(UNIX)
#    SET(PB_LIB_DIR ../base/pb/lib/linux)
#    SET(SECURITY_LIB_DIR ../base/security/lib/linux)
#endif()

add_subdirectory(${ENCRYPT_LIB_DIR})
add_subdirectory(${PB_LIB_DIR})
add_subdirectory(${PACK_LIB_DIR})
add_subdirectory(${BUFFER_LIB_DIR})
add_subdirectory(${JSON_LIB_DIR})
add_subdirectory(${LOGGER_LIB_DIR})
add_subdirectory(${UNIX_LIB_DIR})

ADD_DEFINITIONS( -g -W -Wno-deprecated -D_REENTRANT -D_FILE_OFFSET_BITS=64 -DAC_HAS_INFO
-DAC_HAS_WARNING -DAC_HAS_ERROR -DAC_HAS_CRITICAL -DTIXML_USE_STL
-DAC_HAS_DEBUG -DLINUX_DAEMON -std=c++11)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}  SRC_LIST)
INCLUDE_DIRECTORIES(./ ./encrypt ./pb ./pack ./buffer ./json ./logger ./include ./include/libuv   ./include/openssl ./include/libsignal)
LINK_DIRECTORIES(./ ../lib ./lib)
#ADD_XXXX必须在TARGET_LINK_LIBRARIES前面，否则会报错
ADD_EXECUTABLE(presureClient ${SRC_LIST})
TARGET_LINK_LIBRARIES(presureClient pack pb encrypt buffer json logger unix log4cplus uv pthread crypto protobuf signal-protocol-c)
 
