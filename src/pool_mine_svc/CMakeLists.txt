set(LIBRARIES
  poolinstances
  poolcore
  blockmaker
  poolcommon
  asyncio-0.5
  asyncioextras-0.5
  loguru
  p2putils
)

# OS-specific configuration
if (WIN32)
  set(LIBRARIES ${LIBRARIES} ws2_32 mswsock shlwapi crypt32 rpcrt4)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(LIBRARIES ${LIBRARIES} dl jemalloc)
endif()

# Compiler-specific configuration
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(LIBRARIES ${LIBRARIES}
    atomic
    pthread
    stdc++fs
  )
endif()

add_executable(pool_mine_svc
  main.cpp
  config.cpp
)

target_link_libraries(pool_mine_svc
  ${LIBRARIES}
)
