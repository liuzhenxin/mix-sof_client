include_directories(../../include)


add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL)

set(
    ARCH_SOURCES
    #cpu-arm.c
)

IF(WIN32)
  IF (MSVC)
    IF (MSVC_VERSION EQUAL 1700)
      set(CMAKE_GENERATOR_TOOLSET "v110_xp" CACHE STRING "Platform Toolset" FORCE)
    ELSEIF (MSVC_VERSION EQUAL 1800)
      set(CMAKE_GENERATOR_TOOLSET "v120_xp" CACHE STRING "Platform Toolset" FORCE)
    ELSEIF (MSVC_VERSION EQUAL 1900)
      set(CMAKE_GENERATOR_TOOLSET "v140_xp" CACHE STRING "Platform Toolset" FORCE)
    ENDIF()
  ENDIF(MSVC)
ENDIF(WIN32)

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

FILE(GLOB 
  common_cs 
  ${CMAKE_SOURCE_DIR}/common/FILE_LOG.c 
  ${CMAKE_SOURCE_DIR}/common/modp_b64.c 
  ${CMAKE_SOURCE_DIR}/common/o_all_func_def.c 
  ${CMAKE_SOURCE_DIR}/common/openssl_func_def.c 
  )

FILE(GLOB 
  common_cpps
  ${CMAKE_SOURCE_DIR}/common/smcert.cpp
  ${CMAKE_SOURCE_DIR}/common/encode_switch.cpp
  ${CMAKE_SOURCE_DIR}/common/certificate_items_parse.cpp
 )

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)


ADD_LIBRARY(
  sof_client SHARED
  
  smb_base.rc
  smb_base.def
  ${common_cs} 
  ${common_cpps} 
)

target_link_libraries(sof_client sqlite3)



