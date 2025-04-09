#pragma once

#include "ltc.h"
#include "poolinstances/stratumWorkStorage.h"

namespace DOGE {
class Proto {
public:
  static constexpr const char *TickerName = "DOGE";

  using BlockHashTy = BTC::Proto::BlockHashTy;
  using TxHashTy = BTC::Proto::TxHashTy;
  using AddressTy = BTC::Proto::AddressTy;

  using PureBlockHeader = LTC::Proto::BlockHeader;

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

  using Block = BTC::Proto::BlockTy<DOGE::Proto>;

  using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
  using ChainParams = BTC::Proto::ChainParams;

  static void checkConsensusInitialize(CheckConsensusCtx&) {}
  static CCheckStatus checkConsensus(const Proto::BlockHeader &header, CheckConsensusCtx&, Proto::ChainParams&) {
    return header.nVersion & Proto::BlockHeader::VERSION_AUXPOW ?
      LTC::Proto::checkPow(header.ParentBlock, header.nBits) :
      LTC::Proto::checkPow(header, header.nBits);
  }

  static CCheckStatus checkConsensus(const Proto::Block &block, CheckConsensusCtx &ctx, Proto::ChainParams &chainParams) { return checkConsensus(block.header, ctx, chainParams); }
  static double getDifficulty(const Proto::BlockHeader &header) { return BTC::difficultyFromBits(header.nBits, 29); }
  static double expectedWork(const Proto::BlockHeader &header, const CheckConsensusCtx&) { return getDifficulty(header); }
  static bool decodeHumanReadableAddress(const std::string &hrAddress, const std::vector<uint8_t> &pubkeyAddressPrefix, AddressTy &address) { return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address); }
};

class Stratum {
public:
  static constexpr double DifficultyFactor = 65536.0;
  using MiningConfig = BTC::Stratum::MiningConfig;
  using StratumMessage = BTC::Stratum::StratumMessage;
  using CSingleWork = StratumSingleWork<Proto::BlockHashTy, MiningConfig, StratumMessage>;
  using CMergedWork = StratumMergedWork<Proto::BlockHashTy, MiningConfig, StratumMessage>;

  using Work = BTC::WorkTy<DOGE::Proto, BTC::Stratum::HeaderBuilder, BTC::Stratum::CoinbaseBuilder, BTC::Stratum::Notify, BTC::Stratum::Prepare, MiningConfig, StratumMessage>;
  using SecondWork = LTC::Stratum::Work;
  class MergedWork : public CMergedWork {
  public:
    MergedWork(uint64_t stratumWorkId, CSingleWork *first, CSingleWork *second, MiningConfig &miningCfg);

    virtual Proto::BlockHashTy shareHash() override {
      return LTCHeader_.GetHash();
    }

    virtual std::string blockHash(size_t workIdx) override {
      if (workIdx == 0)
        return DOGEHeader_.GetHash().ToString();
      else if (workIdx == 1)
        return LTCHeader_.GetHash().ToString();
      else
        return std::string();
    }

    virtual void mutate() override {
      LTCHeader_.nTime = static_cast<uint32_t>(time(nullptr));
      LTC::Stratum::Work::buildNotifyMessageImpl(this, LTCHeader_, LTCHeader_.nVersion, LTCLegacy_, LTCMerklePath_, MiningCfg_, true, NotifyMessage_);
    }

    virtual void buildNotifyMessage(bool resetPreviousWork) override {
      LTC::Stratum::Work::buildNotifyMessageImpl(this, LTCHeader_, LTCHeader_.nVersion, LTCLegacy_, LTCMerklePath_, MiningCfg_, resetPreviousWork, NotifyMessage_);
    }

    virtual bool prepareForSubmit(const CWorkerConfig &workerCfg, const StratumMessage &msg) override;

    virtual void buildBlock(size_t workIdx, xmstream &blockHexData) override {
      if (workIdx == 0) {
        dogeWork()->buildBlockImpl(DOGEHeader_, DOGEWitness_, blockHexData);
      } else if (workIdx == 1) {
        ltcWork()->buildBlockImpl(LTCHeader_, LTCWitness_, blockHexData);
      }
    }

    virtual CCheckStatus checkConsensus(size_t workIdx) override {
      if (workIdx == 0)
        return DOGE::Stratum::Work::checkConsensusImpl(DOGEHeader_, LTCConsensusCtx_);
      else if (workIdx == 1)
        return LTC::Stratum::Work::checkConsensusImpl(LTCHeader_, DOGEConsensusCtx_);
      return CCheckStatus();
    }

  private:
    DOGE::Stratum::Work *dogeWork() { return static_cast<DOGE::Stratum::Work*>(Works_[0]); }
    LTC::Stratum::Work *ltcWork() { return static_cast<LTC::Stratum::Work*>(Works_[1]); }

  private:
    LTC::Proto::BlockHeader LTCHeader_;
    BTC::CoinbaseTx LTCLegacy_;
    BTC::CoinbaseTx LTCWitness_;
    std::vector<uint256> LTCMerklePath_;
    LTC::Proto::CheckConsensusCtx LTCConsensusCtx_;

    DOGE::Proto::BlockHeader DOGEHeader_;
    BTC::CoinbaseTx DOGELegacy_;
    BTC::CoinbaseTx DOGEWitness_;
    DOGE::Proto::CheckConsensusCtx DOGEConsensusCtx_;
  };

  static constexpr bool MergedMiningSupport = true;
  static void workerConfigInitialize(CWorkerConfig &workerCfg, ThreadConfig &threadCfg) { BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg); }
  static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) { BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask); }
  static void workerConfigOnSubscribe(CWorkerConfig &workerCfg, BTC::MiningConfig &miningCfg, StratumMessage &msg, xmstream &out, std::string &subscribeInfo) {
    BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo);
  }

  static bool isMainBackend(const std::string &ticker) { return ticker == "DOGE" || ticker == "DOGE.testnet" || ticker == "DOGE.regtest"; }
  static bool keepOldWorkForBackend(const std::string&) { return false; }
  static void buildSendTargetMessage(xmstream &stream, double difficulty) { BTC::Stratum::buildSendTargetMessageImpl(stream, difficulty, DifficultyFactor); }
};

struct X {
  using Proto = DOGE::Proto;
  using Stratum = DOGE::Stratum;
  template<typename T> static inline void serialize(xmstream &src, const T &data) { BTC::Io<T>::serialize(src, data); }
  template<typename T> static inline void unserialize(xmstream &dst, T &data) { BTC::Io<T>::unserialize(dst, data); }
};
}

// Header
namespace BTC {
template<> struct Io<DOGE::Proto::BlockHeader> {
  static void serialize(xmstream &dst, const DOGE::Proto::BlockHeader &data);
  static void unserialize(xmstream &src, DOGE::Proto::BlockHeader &data);
};
}

void serializeJsonInside(xmstream &stream, const DOGE::Proto::BlockHeader &header);
