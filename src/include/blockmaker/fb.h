#pragma once

#include "blockmaker/btc.h"
#include "poolinstances/stratumWorkStorage.h"

// Namecoin-style AuxPoW secondary for a BTC primary
namespace FB {
class Proto {
public:
  static constexpr const char *TickerName = "FB";

  using BlockHashTy   = BTC::Proto::BlockHashTy;
  using TxHashTy      = BTC::Proto::TxHashTy;
  using AddressTy     = BTC::Proto::AddressTy;
  using PureBlockHeader = BTC::Proto::BlockHeader;

  // We store AuxPoW fields alongside the pure header for local assembly
  struct BlockHeader : public PureBlockHeader {
  public:
    static const int32_t VERSION_AUXPOW = (1 << 8);
    // AuxPoW payload (for submit)
    Transaction ParentBlockCoinbaseTx;        // Parent (BTC) coinbase transaction
    BTC::Proto::BlockHashTy HashBlock;        // FB block hash (after we compute it)
    xvector<uint256> MerkleBranch;            // Parent (BTC) merkle path to coinbase
    int Index = 0;                            // Parent coinbase index in tree

    // Chain merkle (virtual tree that combines multiple secondaries)
    xvector<uint256> ChainMerkleBranch;
    int ChainIndex = 0;

    // Full parent header snapshot used in auxpow
    PureBlockHeader ParentBlock;
  };

  using Transaction = BTC::Proto::Transaction;
  using Block       = BTC::Proto::BlockTy<FB::Proto>;

  using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
  using ChainParams       = BTC::Proto::ChainParams;

  static void checkConsensusInitialize(CheckConsensusCtx&) {}
  static CCheckStatus checkConsensus(const Proto::BlockHeader &header, CheckConsensusCtx&, Proto::ChainParams&) {
    // For FB merged mining: if AuxPoW bit set, check parent BTC header PoW, otherwise check FB header PoW
    return header.nVersion & Proto::BlockHeader::VERSION_AUXPOW ?
      BTC::Proto::checkPow(header.ParentBlock, header.ParentBlock.nBits) :
      BTC::Proto::checkPow(static_cast<const BTC::Proto::BlockHeader&>(header), header.nBits);
  }

  static CCheckStatus checkConsensus(const Proto::Block &block, CheckConsensusCtx &ctx, ChainParams &chainParams) {
    return checkConsensus(block.header, ctx, chainParams);
  }

  static double getDifficulty(const Proto::BlockHeader &h) { return BTC::difficultyFromBits(h.nBits, 32); }
  static double expectedWork(const Proto::BlockHeader &h, const CheckConsensusCtx&) { return getDifficulty(h); }
  static bool decodeHumanReadableAddress(const std::string &hr, const std::vector<uint8_t> &pubkeyPrefix, AddressTy &address) {
    return BTC::Proto::decodeHumanReadableAddress(hr, pubkeyPrefix, address);
  }
};

// Stratum binding similar to DOGE::Stratum, but BTC is the parent.
class Stratum {
public:
  using Proto = FB::Proto;
  static constexpr bool MergedMiningSupport = true;

  static constexpr double DifficultyFactor = 1.0; // same as BTC
  using FBWork = BTC::WorkTy<FB::Proto, BTC::Stratum::HeaderBuilder, BTC::Stratum::CoinbaseBuilder, BTC::Stratum::Notify, BTC::Stratum::Prepare>;

  class MergedWork : public StratumMergedWork {
  public:
    MergedWork(uint64_t stratumWorkId,
               StratumSingleWork *first,                          // BTC primary
               std::vector<StratumSingleWork*> &second,           // FB secondaries (usually size 1)
               std::vector<int> &mmChainId,
               uint32_t mmNonce,
               unsigned int virtualHashesNum,
               const CMiningConfig &miningCfg);

    virtual Proto::BlockHashTy shareHash() override { return BTCHeader_.GetHash(); }

    virtual std::string blockHash(size_t workIdx) override;
    virtual void buildBlock(size_t workIdx, xmstream &blockHexData) override;
    virtual bool prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg) override;
    virtual CCheckStatus checkConsensus(size_t workIdx) override;
    virtual void mutate() override;
    virtual void buildNotifyMessage(bool resetPreviousWork) override;

  private:
    BTC::Stratum::Work *btcWork() { return static_cast<BTC::Stratum::Work*>(Works_[0].Work); }
    FB::Stratum::FBWork *fbWork(unsigned index) { return static_cast<FB::Stratum::FBWork*>(Works_[index + 1].Work); }

  private:
    // Parent (BTC)
    BTC::Proto::BlockHeader BTCHeader_;
    BTC::CoinbaseTx BTCLegacy_;
    BTC::CoinbaseTx BTCWitness_;
    std::vector<uint256> BTCMerklePath_;
    BTC::Proto::CheckConsensusCtx BTCConsensusCtx_;

    // Secondaries (FB)
    std::vector<FB::Proto::BlockHeader> FBHeader_;
    std::vector<BTC::CoinbaseTx> FBLegacy_;
    std::vector<BTC::CoinbaseTx> FBWitness_;
    std::vector<uint256> FBHeaderHashes_;
    std::vector<int> FBWorkMap_;
    FB::Proto::CheckConsensusCtx FBConsensusCtx_;
  };

  // Primary work is BTC
  static BTC::Stratum::Work *newPrimaryWork(int64_t stratumId,
                                            PoolBackend *backend,
                                            size_t backendIdx,
                                            const CMiningConfig &miningCfg,
                                            const std::vector<uint8_t> &miningAddress,
                                            const std::string &coinbaseMessage,
                                            CBlockTemplate &blockTemplate,
                                            std::string &error)
  {
    return BTC::Stratum::newPrimaryWork(stratumId, backend, backendIdx, miningCfg, miningAddress, coinbaseMessage, blockTemplate, error);
  }

  // Secondary work is FB (AuxPoW)
  static FBWork *newSecondaryWork(int64_t stratumId,
                                  PoolBackend *backend,
                                  size_t backendIdx,
                                  const CMiningConfig &miningCfg,
                                  const std::vector<uint8_t> &miningAddress,
                                  const std::string &coinbaseMessage,
                                  CBlockTemplate &blockTemplate,
                                  std::string &error);

  static StratumMergedWork *newMergedWork(int64_t stratumId,
                                          StratumSingleWork *first,
                                          std::vector<StratumSingleWork*> &second,
                                          const CMiningConfig &miningCfg,
                                          std::string &error);

  static void buildSendTargetMessage(xmstream &stream, double diff) {
    BTC::Stratum::buildSendTargetMessage(stream, diff);
  }

  static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg, const char *in, size_t size) { return BTC::Stratum::decodeStratumMessage(msg, in, size); }

  static void miningConfigInitialize(CMiningConfig &cfg, rapidjson::Value &config) {
    BTC::Stratum::miningConfigInitialize(cfg, config);
  }

  static void workerConfigInitialize(CWorkerConfig &cfg, ThreadConfig &threadCfg) {
    BTC::Stratum::workerConfigInitialize(cfg, threadCfg);
  }

  // Called during mining.subscribe to set extranonce, etc.
  static void workerConfigOnSubscribe(CWorkerConfig &workerCfg, CMiningConfig &miningCfg, CStratumMessage &msg, xmstream &out, std::string &subscribeInfo) {
    BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo);
  }

  static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) { BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask); }

  template<typename T> static inline void serialize(xmstream &src, const T &data) { BTC::Io<T>::serialize(src, data); }
  template<typename T> static inline void unserialize(xmstream &dst, T &data) { BTC::Io<T>::unserialize(dst, data); }
};

struct X {
  using Proto = FB::Proto;
  using Stratum = FB::Stratum;

  template<typename T> static inline void serialize(xmstream &src, const T &data) { BTC::Io<T>::serialize(src, data); }
  template<typename T> static inline void unserialize(xmstream &dst, T &data) { BTC::Io<T>::unserialize(dst, data); }
};
}

// JSON serialization for debugging / logs if needed
namespace BTC {
template<> struct Io<FB::Proto::BlockHeader> {
  static void serialize(xmstream &dst, const FB::Proto::BlockHeader &data);
  static void unserialize(xmstream &src, FB::Proto::BlockHeader &data);
};
}

void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header);
