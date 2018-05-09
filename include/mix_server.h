#ifndef MIX_SERVER_H
#define MIX_SERVER_H

#include "common.h"
#include <string>

class FBWTSofPluginAPI;

COMMON_API int http_server_command_exec(std::string pfmtCommandIn, std::string &pfmtCommandOut, FBWTSofPluginAPI *pFBWTSofPluginAPI);

#endif /* MIX_SERVER_H */




