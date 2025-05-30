include("cmake/cxx-pm.cmake")
cxxpm_initialize(
  https://github.com/eXtremal-ik7/cxx-pm/archive/refs/tags/0.0.4.tar.gz
  409fdb16b267926d0cae526041f6b6174fe17b7170519e3d35ae2486e9139f1a
)

cmake_minimum_required(VERSION 3.11)
project(poolcore)
set (CMAKE_CXX_STANDARD 20)

if (SANITIZER_ENABLED)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
endif()

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake
)

if(MSVC)
  add_definitions(
    -D_CRT_SECURE_NO_DEPRECATE
    -D_CRT_SECURE_NO_WARNINGS
    -D_CRT_NONSTDC_NO_DEPRECATE
    -D__STDC_LIMIT_MACROS
    -D__STDC_FORMAT_MACROS
    -DNOMINMAX
    -DNOGDI
  )

  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GR-")
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/msvc/include)
else(MSVC)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fno-rtti")
  if (CXXPM_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcx16")
  endif()
endif(MSVC)

set(protobuf_MODULE_COMPATIBLE TRUE)

cxxpm_add_package(one-tbb default)
cxxpm_add_package(rocksdb default)
cxxpm_add_package(rapidjson default)
cxxpm_add_package(protobuf default)
cxxpm_add_package(libsodium default)
if (NOT MSVC)
  cxxpm_add_package(gmp default)
  set(BIGNUM_LIBRARIES gmp::libgmp gmp::libgmpxx)
else()
  cxxpm_add_package(mpir default)
  set(BIGNUM_LIBRARIES ${MPIR_LIBRARIES})
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ProjectLibp2p.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ProjectSecp256k1.cmake)
add_definitions(-DGOOGLE_PROTOBUF_NO_RTTI)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  add_definitions(-fPIC)
endif ()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

include_directories(
  ${libp2p_SOURCE_DIR}/src/include
  ${libp2p_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/include
)

# Logging library
add_library(loguru STATIC ${CMAKE_CURRENT_SOURCE_DIR}/loguru/loguru.cpp)

add_subdirectory(blockmaker)
add_subdirectory(poolcommon)
add_subdirectory(poolcore)
add_subdirectory(poolinstances)

# Pool service applications
add_subdirectory(pool_accounting_svc)
add_subdirectory(pool_coinprice_svc)
add_subdirectory(pool_mine_svc)
add_subdirectory(pool_stats_svc)
add_subdirectory(pool_master_svc)
