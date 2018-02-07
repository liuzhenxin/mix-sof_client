/**
 * Created by LQQ on 2017/11/13.
 */
#ifndef _SKF_H_
#define _SKF_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "skft.h"

#define __PASTE(x,y)      x##y


/* packing defines */
#include "skfp.h"
/* ==============================================================
 * Define the "extern" form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_SKF_FUNCTION_INFO(name) \
  CK_DECLARE_FUNCTION(ULONG, name)

#include "skff.h"

#undef CK_NEED_ARG_LIST
#undef CK_SKF_FUNCTION_INFO

#define CK_NEED_ARG_LIST  1
#define CK_SKF_FUNCTION_INFO(name) \
  typedef CK_DECLARE_FUNCTION_POINTER(ULONG, __PASTE(CK_,name))

#include "skff.h"

#undef CK_NEED_ARG_LIST
#undef CK_SKF_FUNCTION_INFO

#define CK_SKF_FUNCTION_INFO(name) \
  __PASTE(CK_,name) name;

struct CK_SKF_FUNCTION_LIST {
    void * hHandle;
  #include "skff.h"
};

#undef CK_SKF_FUNCTION_INFO

#undef __PASTE

/* unpack */
#include "skfu.h"

#ifdef __cplusplus
}
#endif

#endif
