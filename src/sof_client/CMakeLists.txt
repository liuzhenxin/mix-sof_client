include_directories(../../include)
include_directories(../../include/xmlsec_inc/iconv)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)

add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL -DXMLSEC_CRYPTO_DYNAMIC_LOADING)


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


  #xmlsec.src/app.c
  #xmlsec.src/base64.c
  #xmlsec.src/bn.c
  #xmlsec.src/buffer.c
  #xmlsec.src/c14n.c
  #xmlsec.src/dl.c
  #xmlsec.src/enveloped.c
  #xmlsec.src/errors.c
  #xmlsec.src/io.c
  #xmlsec.src/keyinfo.c
  #xmlsec.src/keys.c
  #xmlsec.src/keysdata.c
  #xmlsec.src/keysmngr.c
  #xmlsec.src/kw_aes_des.c
  #xmlsec.src/list.c
  #xmlsec.src/membuf.c
  #xmlsec.src/nodeset.c
  #xmlsec.src/parser.c
  #xmlsec.src/relationship.c
  #xmlsec.src/strings.c
  #xmlsec.src/templates.c
  #xmlsec.src/transforms.c
  #xmlsec.src/x509.c
  #xmlsec.src/xmldsig.c
  #xmlsec.src/xmlenc.c
  #xmlsec.src/xmlsec.c
  #xmlsec.src/xmltree.c
  #xmlsec.src/xpath.c
  #xmlsec.src/xslt.c
  
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

target_link_libraries(sof_client libxmlsec)

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




