#pragma once

#include "btc.h"
#include "serialize.h"
#include "blockmaker/stratumWork.h"

namespace DASH {

// ====== Protocol Definitions (inherits from BTC) ======
class Proto {
public:
  static constexpr const char *TickerName = "DASH";

  using BlockHashTy = BTC::Proto::BlockHashTy;
  using TxHashTy = BTC::Proto::TxHashTy;
  using AddressTy = BTC::Proto::AddressTy;
  using BlockHeader = BTC::Proto::BlockHeader;
  using Block = BTC::Proto::Block;
  using TxIn = BTC::Proto::TxIn;
  using TxOut = BTC::Proto::TxOut;
  using TxWitness = BTC::Proto::TxWitness;

  struct Transaction {
    int32_t version;
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    uint32_t lockTime;
    std::vector<uint8_t> vExtraPayload;

    bool hasExtraPayload() const {
      return !vExtraPayload.empty();
    }
  };

  using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
  using ChainParams = BTC::Proto::ChainParams;

  static CCheckStatus checkPow(const BlockHeader &header, uint32_t nBits) {
    return BTC::Proto::checkPow(header, nBits);
  }

  static void checkConsensusInitialize(CheckConsensusCtx&) {}

  static CCheckStatus checkConsensus(const BlockHeader &header, CheckConsensusCtx &ctx, ChainParams &params) {
    return checkPow(header, header.nBits);
  }

  static CCheckStatus checkConsensus(const Block &block, CheckConsensusCtx &ctx, ChainParams &params) {
    return checkPow(block.header, block.header.nBits);
  }

  static double getDifficulty(const BlockHeader &header) {
    return BTC::difficultyFromBits(header.nBits, 29);
  }

  static double expectedWork(const BlockHeader &header, const CheckConsensusCtx&) {
    return getDifficulty(header);
  }

  static bool decodeHumanReadableAddress(const std::string &hrAddress, const std::vector<uint8_t> &pubkeyAddressPrefix, AddressTy &address) {
    return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address);
  }
};


// ====== Stratum Logic ======
class Stratum {
public:
  static constexpr double DifficultyFactor = 65536.0;
  static constexpr bool MergedMiningSupport = false;

  using Work = BTC::WorkTy<
    DASH::Proto,
    BTC::Stratum::HeaderBuilder,
    BTC::Stratum::CoinbaseBuilder,
    BTC::Stratum::Notify,
    BTC::Stratum::Prepare
  >;

  static Work *newPrimaryWork(int64_t stratumId,
                              PoolBackend *backend,
                              size_t backendIdx,
                              const CMiningConfig &miningCfg,
                              const std::vector<uint8_t> &miningAddress,
                              const std::string &coinbaseMessage,
                              CBlockTemplate &blockTemplate,
                              std::string &error) {
    if (blockTemplate.WorkType != EWorkBitcoin) {
      error = "incompatible work type";
      return nullptr;
    }

    std::unique_ptr<Work> work(new Work(stratumId,
                                        blockTemplate.UniqueWorkId,
                                        backend,
                                        backendIdx,
                                        miningCfg,
                                        miningAddress,
                                        coinbaseMessage));
    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
  }

  static StratumSingleWork *newSecondaryWork(...) { return nullptr; }
  static StratumMergedWork *newMergedWork(...) { return nullptr; }

  static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg, const char *in, size_t size) {
    return BTC::Stratum::decodeStratumMessage(msg, in, size);
  }

  static void miningConfigInitialize(CMiningConfig &cfg, rapidjson::Value &json) {
    BTC::Stratum::miningConfigInitialize(cfg, json);
  }

  static void workerConfigInitialize(CWorkerConfig &workerCfg, ThreadConfig &threadCfg) {
    BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg);
  }

  static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
    BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
  }

  static void workerConfigOnSubscribe(CWorkerConfig &workerCfg, CMiningConfig &miningCfg, CStratumMessage &msg, xmstream &out, std::string &subscribeInfo) {
    BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo);
  }

  static void buildSendTargetMessage(xmstream &stream, double difficulty) {
    BTC::Stratum::buildSendTargetMessageImpl(stream, difficulty, DifficultyFactor);
  }
};


// ====== Stratum Adapter for StratumInstance<X> ======
struct X {
  using Proto = DASH::Proto;
  using Stratum = DASH::Stratum;

  template<typename T>
  static inline void serialize(xmstream &src, const T &data) {
    BTC::Io<T>::serialize(src, data);
  }

  template<typename T>
  static inline void unserialize(xmstream &dst, T &data) {
    BTC::Io<T>::unserialize(dst, data);
  }
};

} // namespace DASH