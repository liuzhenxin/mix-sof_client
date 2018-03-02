include_directories(../../include)


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