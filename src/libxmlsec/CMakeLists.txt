
include_directories(../../include/xmlsec_inc/iconv)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)
include_directories(../../include/xmlsec_inc/)
include_directories(./include/)

add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL -DPACKAGE=\"xmlsec\" -DXMLSEC_DL_WIN32 -DIN_XMLSEC -D_WIN32 -DIN_XMLSEC_CRYPTO)

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


ADD_LIBRARY(
  libxmlsec-openssl SHARED

  app.c
  base64.c
  bn.c
  buffer.c
  c14n.c
  dl.c
  enveloped.c
  errors.c
  io.c
  keyinfo.c
  keys.c
  keysdata.c
  keysmngr.c
  kw_aes_des.c
  list.c
  membuf.c
  nodeset.c
  parser.c
  relationship.c
  strings.c
  templates.c
  transforms.c
  x509.c
  xmldsig.c
  xmlenc.c
  xmlsec.c
  xmltree.c
  xpath.c
  xslt.c


  openssl/app.c
  openssl/bn.c
  openssl/ciphers.c
  openssl/crypto.c
  openssl/digests.c
  openssl/evp.c
  openssl/evp_signatures.c
  openssl/hmac.c
  openssl/kw_aes.c
  openssl/kw_des.c
  openssl/kt_rsa.c
  openssl/signatures.c
  openssl/symkeys.c
  openssl/x509.c
  openssl/x509vfy.c 
)


target_link_libraries(libxmlsec-openssl libxml2)
target_link_libraries(libxmlsec-openssl libxslt)
target_link_libraries(libxmlsec-openssl libcrypto)



