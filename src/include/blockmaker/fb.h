#pragma once

#include "blockmaker/btc.h"
#include "poolinstances/stratumWorkStorage.h"

namespace FB {
class Proto {
public:
  static constexpr const char *TickerName = "FB";

  using BlockHashTy = BTC::Proto::BlockHashTy;
  using TxHashTy = BTC::Proto::TxHashTy;
  using AddressTy = BTC::Proto::AddressTy;

  using PureBlockHeader = BTC::Proto::BlockHeader;

  using TxIn = BTC::Proto::TxIn;
  using TxOut = BTC::Proto::TxOut;
  using TxWitness = BTC::Proto::TxWitness;
  using Transaction = BTC::Proto::Transaction;

  struct BlockHeader: public PureBlockHeader {
  public:
    static const int32_t VERSION_AUXPOW = (1 << 8);
    // AuxPow
    Transaction ParentBlockCoinbaseTx;
    uint256 HashBlock;
    xvector<uint256> MerkleBranch;
    int Index;
    xvector<uint256> ChainMerkleBranch;
    int ChainIndex;
    PureBlockHeader ParentBlock;
  };

  using Block = BTC::Proto::BlockTy<FB::Proto>;

  using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
  using ChainParams = BTC::Proto::ChainParams;

  static void checkConsensusInitialize(CheckConsensusCtx&) {}

  static CCheckStatus checkConsensus(const Proto::BlockHeader &header, CheckConsensusCtx &ctx, Proto::ChainParams &params) {
    return header.nVersion & Proto::BlockHeader::VERSION_AUXPOW ?
      BTC::Proto::checkConsensus(header.ParentBlock, ctx, params) :
      BTC::Proto::checkConsensus(static_cast<const BTC::Proto::BlockHeader&>(header), ctx, params);
  }

  static CCheckStatus checkConsensus(const Proto::Block &block, CheckConsensusCtx &ctx, Proto::ChainParams &params) { return checkConsensus(block.header, ctx, params); }
  static double getDifficulty(const Proto::BlockHeader &header) { return BTC::difficultyFromBits(header.nBits, 32); }
  static double expectedWork(const Proto::BlockHeader &header, const CheckConsensusCtx&) { return getDifficulty(header); }
  static bool decodeHumanReadableAddress(const std::string &hrAddress, const std::vector<uint8_t> &pubkeyAddressPrefix, AddressTy &address) { return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address); }
};

class Stratum {
public:
  using Proto = FB::Proto;
  static constexpr bool MergedMiningSupport = true;

  static constexpr double DifficultyFactor = 1.0; // BTC-style targets
  using FBWork = BTC::WorkTy<FB::Proto, BTC::Stratum::HeaderBuilder, BTC::Stratum::CoinbaseBuilder, BTC::Stratum::Notify, BTC::Stratum::Prepare>;

  class MergedWork : public StratumMergedWork {
  public:
    MergedWork(uint64_t stratumWorkId,
               StratumSingleWork *first,
               std::vector<StratumSingleWork*> &second,
               std::vector<int> &mmChainId,
               uint32_t mmNonce,
               unsigned int virtualHashesNum,
               const CMiningConfig &miningCfg);

    virtual Proto::BlockHashTy shareHash() override {
      return BTCHeader_.GetHash();
    }

    virtual std::string blockHash(size_t workIdx) override {
      if (workIdx == 0)
        return BTCHeader_.GetHash().ToString();
      else if (workIdx - 1 < FBHeader_.size())
        return FBHeader_[workIdx - 1].GetHash().ToString();
      else
        return std::string();
    }

    virtual void mutate() override {
      BTCHeader_.nTime = static_cast<uint32_t>(time(nullptr));
      BTC::Stratum::Work::buildNotifyMessageImpl(this, BTCHeader_, BTCHeader_.nVersion, BTCLegacy_, BTCMerklePath_, MiningCfg_, true, NotifyMessage_);
    }

    virtual void buildNotifyMessage(bool resetPreviousWork) override {
      BTC::Stratum::Work::buildNotifyMessageImpl(this, BTCHeader_, BTCHeader_.nVersion, BTCLegacy_, BTCMerklePath_, MiningCfg_, resetPreviousWork, NotifyMessage_);
    }

    virtual bool prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg) override;

    virtual void buildBlock(size_t workIdx, xmstream &blockHexData) override {
      if (workIdx == 0 && btcWork()) {
        btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
      } else if (fbWork(workIdx - 1)) {
        fbWork(workIdx - 1)->buildBlockImpl(FBHeader_[workIdx - 1], FBWitness_[workIdx - 1], blockHexData);
      }
    }

    virtual CCheckStatus checkConsensus(size_t workIdx) override {
      if (workIdx == 0 && btcWork())
        return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, BTCConsensusCtx_);
      else if (fbWork(workIdx - 1))
        return FB::Stratum::FBWork::checkConsensusImpl(FBHeader_[workIdx - 1], FBConsensusCtx_);
      return CCheckStatus();
    }

  private:
    BTC::Stratum::Work *btcWork() { return static_cast<BTC::Stratum::Work*>(Works_[0].Work); }
    FB::Stratum::FBWork *fbWork(unsigned index) { return static_cast<FB::Stratum::FBWork*>(Works_[index + 1].Work); }

  private:
    BTC::Proto::BlockHeader BTCHeader_;
    BTC::CoinbaseTx BTCLegacy_;
    BTC::CoinbaseTx BTCWitness_;
    std::vector<uint256> BTCMerklePath_;
    BTC::Proto::CheckConsensusCtx BTCConsensusCtx_;

    std::vector<FB::Proto::BlockHeader> FBHeader_;
    std::vector<BTC::CoinbaseTx> FBLegacy_;
    std::vector<BTC::CoinbaseTx> FBWitness_;
    std::vector<uint256> FBHeaderHashes_;
    std::vector<int> FBWorkMap_;
    FB::Proto::CheckConsensusCtx FBConsensusCtx_;
  };

  static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary, uint32_t &nonce, unsigned int &virtualHashesNum);

  static BTC::Stratum::Work *newPrimaryWork(int64_t stratumId,
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
    std::unique_ptr<BTC::Stratum::Work> work(new BTC::Stratum::Work(stratumId,
                                        blockTemplate.UniqueWorkId,
                                        backend,
                                        backendIdx,
                                        miningCfg,
                                        miningAddress,
                                        coinbaseMessage));
    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
  }
  static FBWork *newSecondaryWork(int64_t stratumId,
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
    std::unique_ptr<FBWork> work(new FBWork(stratumId,
                                                blockTemplate.UniqueWorkId,
                                                backend,
                                                backendIdx,
                                                miningCfg,
                                                miningAddress,
                                                coinbaseMessage));
    if (!work->loadFromTemplate(blockTemplate, error))
      return nullptr;

    work->Header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
    return work.release();
  }
  static StratumMergedWork *newMergedWork(int64_t stratumId,
                                          StratumSingleWork *primaryWork,
                                          std::vector<StratumSingleWork*> &secondaryWorks,
                                          const CMiningConfig &miningCfg,
                                          std::string &error) {
    if (secondaryWorks.empty()) {
      error = "no secondary works";
      return nullptr;
    }

    uint32_t nonce = 0;
    unsigned virtualHashesNum = 0;
    std::vector<int> chainMap = buildChainMap(secondaryWorks, nonce, virtualHashesNum);
    if (chainMap.empty()) {
      error = "chainId conflict";
      return nullptr;
    }

    return new MergedWork(stratumId, primaryWork, secondaryWorks, chainMap, nonce, virtualHashesNum, miningCfg);
  }

  static void buildSendTargetMessage(xmstream &stream, double difficulty) { BTC::Stratum::buildSendTargetMessageImpl(stream, difficulty, DifficultyFactor); }

  static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg, const char *in, size_t size) { return BTC::Stratum::decodeStratumMessage(msg, in, size); }

  static void miningConfigInitialize(CMiningConfig &cfg, rapidjson::Value &config) { BTC::Stratum::miningConfigInitialize(cfg, config); }

  static void workerConfigInitialize(CWorkerConfig &cfg, ThreadConfig &threadCfg) { BTC::Stratum::workerConfigInitialize(cfg, threadCfg); }

  static void workerConfigOnSubscribe(CWorkerConfig &workerCfg, CMiningConfig &miningCfg, CStratumMessage &msg, xmstream &out, std::string &subscribeInfo) { BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo); }

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

namespace BTC {
template<> struct Io<FB::Proto::BlockHeader> {
  static void serialize(xmstream &dst, const FB::Proto::BlockHeader &data);
};
}

void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header);
