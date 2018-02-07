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
  ${CMAKE_SOURCE_DIR}/sof_client/FILE_LOG.c 
  ${CMAKE_SOURCE_DIR}/sof_client/modp_b64.c 
  ${CMAKE_SOURCE_DIR}/sof_client/o_all_func_def.c 
  ${CMAKE_SOURCE_DIR}/sof_client/openssl_func_def.c 
  )

FILE(GLOB 
  common_cpps
  ${CMAKE_SOURCE_DIR}/sof_client/smcert.cpp
  ${CMAKE_SOURCE_DIR}/sof_client/encode_switch.cpp
  ${CMAKE_SOURCE_DIR}/sof_client/certificate_items_parse.cpp
 )

LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)


ADD_LIBRARY(
  sof_client SHARED
  
  sof_client.rc
  sof_client.def
  sof_client-lib.cpp
  ${common_cs} 
  ${common_cpps} 
)

target_link_libraries(sof_client mix_bssl)



