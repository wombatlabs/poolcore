// dash.h - adapted from btc.h
#pragma once

#include <vector>
#include <cstdint>
#include "uint256.h"
#include "rapidjson/document.h"
#include "blockmaker/coin.h"

namespace DASH {
namespace Proto {

struct BlockHeader {
  int32_t nVersion;
  uint16_t nType; // Dash-specific
  uint256 hashPrevBlock;
  uint256 hashMerkleRoot;
  uint32_t nTime;
  uint32_t nBits;
  uint32_t nNonce;
  uint256 hashStateRoot;   // Optional
  uint256 hashUTXORoot;    // Optional
  std::vector<uint8_t> extraPayload;
};

} // namespace Proto

uint256 getBlockHash(const Proto::BlockHeader &header);

class DashCoin : public Coin {
public:
  static constexpr const char *TickerName = "DASH";
public:
  using BlockHeader = DASH::Proto::BlockHeader;

  DashCoin();
  bool parseBlockTemplate(const rapidjson::Document &doc, BlockHeader &header);
};

// Factory function not required; Dash will be used like BTC, directly via DASH::DashCoin

} // namespace DASH
