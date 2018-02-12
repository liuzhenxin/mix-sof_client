include_directories(../../include)


LINK_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/../lib
)

add_executable(
  x_test

  x_test.cpp
)


target_link_libraries(x_test sof_client)