#ifndef MIX_SERVER_H
#define MIX_SERVER_H

#include "common.h"

#define SERVICE_COMMAND_HEAD_SIZE 32
#define SERVICE_COMMAND_HEAD_DATA
#define SERVICE_COMMAND_TAG_SIZE 1
#define SERVICE_COMMAND_TAG_DATA 'Z'
#define SERVICE_COMMAND_LEN_SIZE 4

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
(n) = ( (unsigned int) (b)[(i)    ] << 24 )        \
| ( (unsigned int) (b)[(i) + 1] << 16 )        \
| ( (unsigned int) (b)[(i) + 2] <<  8 )        \
| ( (unsigned int) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
(b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
(b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
(b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
(b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
    COMMON_API void *run_mix_server_thread(void *);
    COMMON_API int mix_server_command_valid(unsigned char * pfmtCommandIn);
    COMMON_API int mix_server_command_exec(unsigned char * pfmtCommandIn, int ifmtCommandInLen,unsigned char *pfmtCommandOut, int *pifmtCommandInLen);
#ifdef __cplusplus
}
#endif

#endif /* MIX_SERVER_H */




