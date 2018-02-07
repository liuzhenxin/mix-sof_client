cmake_minimum_required (VERSION 2.8.10)

project (mix-x)

set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/MDd" "/MTd" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

##
add_subdirectory(sof_client)


##
add_subdirectory(x_test)



