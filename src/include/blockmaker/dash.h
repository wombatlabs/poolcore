// dash.h
#pragma once

#include "blockmaker/btc.h"
#include "blockmaker/btcLike.h"
#include "serialize.h"

namespace DASH {

namespace Proto {

struct TxIn {
  BTC::Proto::OutPoint previousOutput;
  std::vector<uint8_t> scriptSig;
  uint32_t sequence;
};

struct TxOut {
  int64_t value;
  std::vector<uint8_t> scriptPubKey;
};

struct Transaction {
  int32_t version;
  std::vector<TxIn> vin;
  std::vector<TxOut> vout;
  uint32_t lockTime;
  std::vector<uint8_t> vExtraPayload;
};

using AddressTy = std::vector<uint8_t>;
using BlockHeader = BTC::Proto::BlockHeader;
using Block = BTC::Proto::BlockTemplate<Transaction>;

static bool decodeHumanReadableAddress(const std::string &addr, const std::vector<uint8_t> &prefix, AddressTy &decoded) {
  return BTC::Proto::decodeHumanReadableAddress(addr, prefix, decoded);
}

static CCheckStatus checkConsensus(const BlockHeader &header, CheckConsensusCtx &, ChainParams &) {
  return BTC::checkProofOfWork(header, header.nBits);
}

static CCheckStatus checkConsensus(const Block &block, CheckConsensusCtx &, ChainParams &) {
  return BTC::checkProofOfWork(block.header, block.header.nBits);
}

} // namespace Proto

struct X {
  using Proto = DASH::Proto;
  using Stratum = WorkTy<
    Proto,
    BTC::Stratum::HeaderBuilder,
    BTC::Stratum::CoinbaseBuilder,
    BTC::Stratum::Notify,
    BTC::Stratum::Prepare
  >;
};

} // namespace DASH
