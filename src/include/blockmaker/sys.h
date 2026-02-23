#pragma once

#include "btc.h"
#include "poolinstances/stratumWorkStorage.h"

// NOTE: SYS uses a different getExpectedIndex formula from NMC (uint64_t with
// intermediate modulo). This means SYS and NMC cannot be simultaneously merged
// in the same stratum instance. Use separate SYS.stratum and NMC.stratum
// instances when mining both coins alongside BTC.

namespace SYS {
class Proto {
public:
  static constexpr const char *TickerName = "SYS";

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
    BaseBlob<256> HashBlock;
    xvector<BaseBlob<256>> MerkleBranch;
    int Index;
    xvector<BaseBlob<256>> ChainMerkleBranch;
    int ChainIndex;
    PureBlockHeader ParentBlock;
  };

  using Block = BTC::Proto::BlockTy<SYS::Proto>;

  using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
  using ChainParams = BTC::Proto::ChainParams;

  static void checkConsensusInitialize(CheckConsensusCtx&) {}
  static CCheckStatus checkConsensus(const Proto::BlockHeader &header, CheckConsensusCtx &ctx, Proto::ChainParams &chainParams, const UInt<256> &shareTarget) {
    return header.nVersion & Proto::BlockHeader::VERSION_AUXPOW ?
      BTC::Proto::checkConsensus(header.ParentBlock, ctx, chainParams, shareTarget) :
      BTC::Proto::checkConsensus(header, ctx, chainParams, shareTarget);
  }

  static CCheckStatus checkConsensus(const Proto::Block &block, CheckConsensusCtx &ctx, Proto::ChainParams &chainParams, const UInt<256> &shareTarget) { return checkConsensus(block.header, ctx, chainParams, shareTarget); }
  static double getDifficulty(const Proto::BlockHeader &header) { return BTC::difficultyFromBits(header.nBits, 29); }
  static UInt<256> expectedWork(const Proto::BlockHeader &header, const CheckConsensusCtx&) { return BTC::Stratum::difficultyFromTarget(uint256Compact(header.nBits)); }
  static bool decodeHumanReadableAddress(const std::string &hrAddress, const std::vector<uint8_t> &pubkeyAddressPrefix, AddressTy &address) { return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address); }
};

class Stratum {
public:
  inline static const UInt<256> StratumMultiplier = UInt<256>(1u) << 32;
  using SysWork = BTC::WorkTy<SYS::Proto, BTC::Stratum::HeaderBuilder, BTC::Stratum::CoinbaseBuilder, BTC::Stratum::Notify, BTC::Stratum::Prepare>;

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
      return BTCHeader_.hash();
    }

    virtual std::string blockHash(size_t workIdx) override {
      if (workIdx == 0)
        return BTCHeader_.hash().getHexLE();
      else if (workIdx - 1 < SYSHeader_.size())
        return SYSHeader_[workIdx-1].hash().getHexLE();
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
      } else if (sysWork(workIdx - 1)) {
        sysWork(workIdx - 1)->buildBlockImpl(SYSHeader_[workIdx-1], SYSWitness_[workIdx-1], blockHexData);
      }
    }

    virtual CCheckStatus checkConsensus(size_t workIdx, const UInt<256> &shareTarget) override {
      if (workIdx == 0 && btcWork())
        return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, SYSConsensusCtx_, shareTarget);
      else if (sysWork(workIdx - 1))
        return SYS::Stratum::SysWork::checkConsensusImpl(SYSHeader_[workIdx - 1], BTCConsensusCtx_, shareTarget);
      return CCheckStatus();
    }

  private:
    BTC::Stratum::Work *btcWork() { return static_cast<BTC::Stratum::Work*>(Works_[0].Work); }
    SYS::Stratum::SysWork *sysWork(unsigned index) { return static_cast<SYS::Stratum::SysWork*>(Works_[index + 1].Work); }

  private:
    BTC::Proto::BlockHeader BTCHeader_;
    BTC::CoinbaseTx BTCLegacy_;
    BTC::CoinbaseTx BTCWitness_;
    std::vector<BaseBlob<256>> BTCMerklePath_;
    BTC::Proto::CheckConsensusCtx BTCConsensusCtx_;

    std::vector<SYS::Proto::BlockHeader> SYSHeader_;
    std::vector<BTC::CoinbaseTx> SYSLegacy_;
    std::vector<BTC::CoinbaseTx> SYSWitness_;
    std::vector<BaseBlob<256>> SYSHeaderHashes_;
    std::vector<int> SYSWorkMap_;
    SYS::Proto::CheckConsensusCtx SYSConsensusCtx_;
  };

  static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary, uint32_t &nonce, unsigned int &virtualHashesNum);

  static constexpr bool MergedMiningSupport = true;
  static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg, const char *in, size_t size) { return BTC::Stratum::decodeStratumMessage(msg, in, size); }
  static void miningConfigInitialize(CMiningConfig &miningCfg, rapidjson::Value &instanceCfg) { BTC::Stratum::miningConfigInitialize(miningCfg, instanceCfg); }
  static void workerConfigInitialize(CWorkerConfig &workerCfg, ThreadConfig &threadCfg) { BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg); }
  static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) { BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask); }
  static void workerConfigOnSubscribe(CWorkerConfig &workerCfg, CMiningConfig &miningCfg, CStratumMessage &msg, xmstream &out, std::string &subscribeInfo) {
    BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo);
  }

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

  static SysWork *newSecondaryWork(int64_t stratumId,
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
    std::unique_ptr<SysWork> work(new SysWork(stratumId,
                                              blockTemplate.UniqueWorkId,
                                              backend,
                                              backendIdx,
                                              miningCfg,
                                              miningAddress,
                                              coinbaseMessage));
    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
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

  static void buildSendTargetMessage(xmstream &stream, double difficulty) { BTC::Stratum::buildSendTargetMessageImpl(stream, difficulty); }
  static UInt<256> targetFromDifficulty(const UInt<256> &difficulty) { return BTC::Stratum::targetFromDifficulty(difficulty); }
};

struct X {
  using Proto = SYS::Proto;
  using Stratum = SYS::Stratum;
  template<typename T> static inline void serialize(xmstream &src, const T &data) { BTC::Io<T>::serialize(src, data); }
  template<typename T> static inline void unserialize(xmstream &dst, T &data) { BTC::Io<T>::unserialize(dst, data); }
};
}

// Header
namespace BTC {
template<> struct Io<SYS::Proto::BlockHeader> {
  static void serialize(xmstream &dst, const SYS::Proto::BlockHeader &data);
  static void unserialize(xmstream &src, SYS::Proto::BlockHeader &data);
};
}

void serializeJsonInside(xmstream &stream, const SYS::Proto::BlockHeader &header);
