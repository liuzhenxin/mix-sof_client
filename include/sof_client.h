/**
 * Created by LQQ on 2017/11/13.
 */
#ifndef _SOF_CLIENT_H_
#define _SOF_CLIENT_H_ 1

#include "skf.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "sof_clientt.h"

#define __PASTE(x,y)      x##y


/* packing defines */
#include "sof_clientp.h"
/* ==============================================================
 * Define the "extern" form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_SOF_CLIENT_FUNCTION_INFO(name) \
  CK_DECLARE_FUNCTION(ULONG, name)

#include "sof_clientf.h"

#undef CK_NEED_ARG_LIST
#undef CK_SOF_CLIENT_FUNCTION_INFO

#define CK_NEED_ARG_LIST  1
#define CK_SOF_CLIENT_FUNCTION_INFO(name) \
  typedef CK_DECLARE_FUNCTION_POINTER(ULONG, __PASTE(CK_,name))

#include "sof_clientf.h"

#undef CK_NEED_ARG_LIST
#undef CK_SOF_CLIENT_FUNCTION_INFO

#define CK_SOF_CLIENT_FUNCTION_INFO(name) \
  __PASTE(CK_,name) name;

struct CK_SOF_CLIENT_FUNCTION_LIST {
    void * hHandle;
  #include "sof_clientf.h"
};

#undef CK_SOF_CLIENT_FUNCTION_INFO

#undef __PASTE

/* unpack */
#include "sof_clientu.h"

#ifdef __cplusplus
}
#endif

#endif
