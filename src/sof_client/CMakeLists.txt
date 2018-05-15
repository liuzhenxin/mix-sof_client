include_directories(../../include)
include_directories(../../include/xmlsec_inc/iconv)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)

#add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL -DXMLSEC_CRYPTO_DYNAMIC_LOADING)
add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL -DXMLSEC_CRYPTO_DYNAMIC_LOADING -DSKF_SUPPORT_WT)



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
  ${CMAKE_SOURCE_DIR}/sof_client/modp_b64.cc 
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
  sof_client-tools.cpp
  sqlite3.c
  smb_cs.cpp

  ${common_cs} 
  ${common_cpps} 
)

IF (MSVC_VERSION EQUAL 1900)
 target_link_libraries(sof_client mix_bssl)
 ELSE()
 target_link_libraries(sof_client mix_bssl_shared)
ENDIF()

target_link_libraries(sof_client crypt32)

target_link_libraries(sof_client libxmlsec-openssl)

target_link_libraries(sof_client libxml2)

target_link_libraries(sof_client libxslt)




LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

add_executable(
  x_test

  x_test.cpp
)


target_link_libraries(x_test sof_client)

add_executable(
  x_test_encrypt

  x_test_encrypt.cpp
)

target_link_libraries(x_test_encrypt crypt32)
target_link_libraries(x_test_encrypt cryptui)

add_executable(
  HTTPServer

  mix_server.cpp
  json_reader.cpp
  json_writer.cpp
  json_value.cpp
  HTTPServer.cpp
  FBWTSofPluginAPI.cpp
)

target_link_libraries(HTTPServer sof_client)

add_executable(
  server_

  error.c
  request.c
  response.c
  header.c
  server_.cpp
)


