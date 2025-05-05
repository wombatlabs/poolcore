# Backend library
add_library(blockmaker STATIC
  ethash.c
  scrypt.cpp
  scrypt-sse2.cpp
  tiny_sha3.c

  aes_helper.cpp
  blake.c
  bmw.c
  cubehash.cpp
  echo.cpp
  groestl.c
  jh.c
  keccak.c
  luffa.cpp
  shavite.cpp
  simd.cpp
  skein.cpp
  x11.cpp

  KeccakP-800-reference.cpp
  odocrypt.cpp

  btc.cpp
  btcLike.cpp
  dash.cpp
  dgb.cpp
  doge.cpp
  eth.cpp
  ltc.cpp
  xpm.cpp
  zec.cpp
)

target_link_libraries(blockmaker
  OpenSSL::SSL
  OpenSSL::Crypto
  libsodium::libsodium
  ${BIGNUM_LIBRARIES}
  poolinstances
)

target_include_directories(blockmaker PUBLIC ${RAPIDJSON_INCLUDE_DIRECTORY})
