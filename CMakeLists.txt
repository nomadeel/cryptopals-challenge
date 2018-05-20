add_library(cryptopp SHARED IMPORTED)
set_target_properties(cryptopp PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/cryptopp/libcryptopp.a")

include_directories("${PROJECT_SOURCE_DIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

add_subdirectory(set1)
add_subdirectory(set2)
add_subdirectory(set3)
