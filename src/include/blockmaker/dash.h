#pragma once

#include "blockmaker/btcLike.h"
#include "blockmaker/btc.h"

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

struct BlockHeader : public BTC::Proto::BlockHeader {
  // Inherit everything from BTC::Proto::BlockHeader
};

struct Block : public BTC::Proto::BlockTemplate<Proto::Transaction> {
  // Inherit everything from BTC::Proto::BlockTemplate
};

using AddressTy = std::vector<uint8_t>;

static bool decodeHumanReadableAddress(const std::string &addr, const std::vector<uint8_t> &prefix, AddressTy &decoded) {
  return BTC::Proto::decodeHumanReadableAddress(addr, prefix, decoded);
}

static CCheckStatus checkConsensus(const BlockHeader &header, CheckConsensusCtx &, ChainParams &) {
  return BTC::checkProofOfWork(header.getHash(), header.nBits);
}

static CCheckStatus checkConsensus(const Block &block, CheckConsensusCtx &ctx, ChainParams &params) {
  return checkConsensus(block.header, ctx, params);
}

} // namespace Proto

using X = BTC::Coin<
  Proto::Block,
  Proto::BlockHeader,
  Proto::Transaction,
  Proto::TxIn,
  Proto::TxOut,
  Proto::AddressTy
>;

using Stratum = WorkTy<
  Proto,
  BTC::Stratum::HeaderBuilder,
  BTC::Stratum::CoinbaseBuilder,
  BTC::Stratum::Notify,
  BTC::Stratum::Prepare
>;

static Stratum::Work *newPrimaryWork(int64_t stratumId,
                                     PoolBackend *backend,
                                     unsigned backendIdx,
                                     const CMiningConfig &config,
                                     const std::vector<uint8_t> &miningAddress,
                                     const std::string &coinbaseMsg,
                                     const CBlockTemplate &blockTemplate,
                                     std::string &error) {
  return new typename Stratum::Work(stratumId, backend, backendIdx, config, miningAddress, coinbaseMsg, blockTemplate, error);
}

static Stratum::Work *newSecondaryWork(int64_t stratumId,
                                       PoolBackend *backend,
                                       unsigned backendIdx,
                                       const CMiningConfig &config,
                                       const std::vector<uint8_t> &miningAddress,
                                       const std::string &coinbaseMsg,
                                       const CBlockTemplate &blockTemplate,
                                       std::string &error) {
  return newPrimaryWork(stratumId, backend, backendIdx, config, miningAddress, coinbaseMsg, blockTemplate, error);
}

} // namespace DASH
