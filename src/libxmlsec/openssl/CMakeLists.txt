
include_directories(../../../include/xmlsec_inc/iconv)
include_directories(../../../include/xmlsec_inc/)
include_directories(../../../include/xmlsec_inc/)
include_directories(../../../include/xmlsec_inc/)
include_directories(../../../include/xmlsec_inc/)
include_directories(../include/)

add_definitions(-DUNICODE -D_UNICODE -DNOCRYPT -DMIX_BORINGSSL -D_WIN32 -DIN_XMLSEC_CRYPTO -DXMLSEC_CRYPTO_DYNAMIC_LOADING=1)

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
  bn.c
  ciphers.c
  crypto.c
  digests.c
  evp.c
  evp_signatures.c
  hmac.c
  kw_aes.c
  kw_des.c
  kt_rsa.c
  signatures.c
  symkeys.c
  x509.c
  x509vfy.c 
)

target_link_libraries(libxmlsec-openssl libxmlsec)
target_link_libraries(libxmlsec-openssl libcrypto)