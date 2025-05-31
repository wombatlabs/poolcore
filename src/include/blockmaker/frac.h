#pragma once

#include "btc.h"               // We’ll use BTC::Proto types as our base
#include "poolinstances/stratumWorkStorage.h"

namespace FRAC {

class Proto {
public:
  static constexpr const char *TickerName = "FRAC";

  using BlockHashTy = BTC::Proto::BlockHashTy;
  using TxHashTy    = BTC::Proto::TxHashTy;
  using AddressTy   = BTC::Proto::AddressTy;

  // FRAC uses the same “pure” header fields as BTC (FRAC is SHA-256 based)
  using PureBlockHeader = BTC::Proto::BlockHeader;

  // Inherit BTC-style TxIn/TxOut/Witness/Transaction
  using TxIn       = BTC::Proto::TxIn;
  using TxOut      = BTC::Proto::TxOut;
  using TxWitness  = BTC::Proto::TxWitness;
  using Transaction= BTC::Proto::Transaction;

  struct BlockHeader: public PureBlockHeader {
  public:
    static const int32_t VERSION_AUXPOW = (1 << 8);

    // AuxPoW fields (identical to DOGE style)
    Transaction ParentBlockCoinbaseTx;
    uint256   HashBlock;
    xvector<uint256> MerkleBranch;
    int       Index;
    xvector<uint256> ChainMerkleBranch;
    int       ChainIndex;
    PureBlockHeader ParentBlock;
  };

  using Block = BTC::Proto::BlockTy<FRAC::Proto>;

  using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
  using ChainParams       = BTC::Proto::ChainParams;

  static void checkConsensusInitialize(CheckConsensusCtx&) {}
  static CCheckStatus checkConsensus(const Proto::BlockHeader &header, CheckConsensusCtx&, Proto::ChainParams&);
  static CCheckStatus checkConsensus(const Proto::Block &block, CheckConsensusCtx &ctx, Proto::ChainParams &chainParams) {
    return checkConsensus(block.header, ctx, chainParams);
  }
  static double getDifficulty(const Proto::BlockHeader &header) {
    return BTC::difficultyFromBits(header.nBits, 29);
  }
  static double expectedWork(const Proto::BlockHeader &header, const CheckConsensusCtx&) {
    return getDifficulty(header);
  }
  static bool decodeHumanReadableAddress(const std::string &hrAddress,
                                         const std::vector<uint8_t> &pubkeyAddressPrefix,
                                         AddressTy &address)
  {
    return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address);
  }
};

class Stratum {
public:
  static constexpr double DifficultyFactor = 1.0; 
  using FracWork = BTC::WorkTy<FRAC::Proto,
                               BTC::Stratum::HeaderBuilder,
                               BTC::Stratum::CoinbaseBuilder,
                               BTC::Stratum::Notify,
                               BTC::Stratum::Prepare>;

  // **Enable AuxPoW/Merged-Mining for FRAC:**
  static constexpr bool MergedMiningSupport = true;

  // We’ll implement newPrimaryWork/newSecondaryWork below
  static FracWork *newPrimaryWork(int64_t stratumId,
                                  PoolBackend *backend,
                                  size_t backendIdx,
                                  const CMiningConfig &miningCfg,
                                  const std::vector<uint8_t> &miningAddress,
                                  const std::string &coinbaseMessage,
                                  CBlockTemplate &blockTemplate,
                                  std::string &error);

  static StratumSingleWork *newSecondaryWork(int64_t stratumId,
                                             PoolBackend *backend,
                                             size_t backendIdx,
                                             const CMiningConfig &miningCfg,
                                             const std::vector<uint8_t> &miningAddress,
                                             const std::string &coinbaseMessage,
                                             CBlockTemplate &blockTemplate,
                                             std::string &error);

  // MergedWork: exactly parallel to DOGE’s, but using FRAC::Proto instead of DOGE::Proto
  class MergedWork : public StratumMergedWork {
  public:
    MergedWork(uint64_t stratumWorkId,
               StratumSingleWork *first,
               std::vector<StratumSingleWork*> &second,
               std::vector<int> &mmChainId,
               uint32_t mmNonce,
               unsigned virtualHashesNum,
               const CMiningConfig &miningCfg);

    virtual Proto::BlockHashTy shareHash() override {
      return BaseHeader_.GetHash();
    }

    virtual std::string blockHash(size_t workIdx) override {
      if (workIdx == 0)
        return BaseHeader_.GetHash().ToString();
      else if (workIdx - 1 < FRACHeaders_.size())
        return FRACHeaders_[workIdx - 1].GetHash().ToString();
      else
        return std::string();
    }

    virtual void mutate() override {
      BaseHeader_.nTime = static_cast<uint32_t>(time(nullptr));
      BTC::Stratum::Work::buildNotifyMessageImpl(this, BaseHeader_, BaseHeader_.nVersion, BaseLegacy_, BaseMerklePath_, MiningCfg_, true, NotifyMessage_);
    }

    virtual void buildNotifyMessage(bool resetPreviousWork) override {
      BTC::Stratum::Work::buildNotifyMessageImpl(this, BaseHeader_, BaseHeader_.nVersion, BaseLegacy_, BaseMerklePath_, MiningCfg_, resetPreviousWork, NotifyMessage_);
    }

    virtual bool prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg) override;

    virtual void buildBlock(size_t workIdx, xmstream &blockHexData) override {
      if (workIdx == 0 && baseWork()) {
        baseWork()->buildBlockImpl(BaseHeader_, BaseWitness_, blockHexData);
      } else if (fracWork(workIdx - 1)) {
        fracWork(workIdx - 1)->buildBlockImpl(FRACHeaders_[workIdx - 1], FRACWitness_[workIdx - 1], blockHexData);
      }
    }

    virtual CCheckStatus checkConsensus(size_t workIdx) override {
      if (workIdx == 0 && baseWork()) {
        return BTC::Stratum::Work::checkConsensusImpl(BaseHeader_, FRACConsensusCtx_);
      } else if (fracWork(workIdx - 1)) {
        return FRAC::Stratum::FracWork::checkConsensusImpl(FRACHeaders_[workIdx - 1], BaseConsensusCtx_);
      }
      return CCheckStatus();
    }

  private:
    // Helpers to cast `Works_[i].Work` to the right type
    BTC::Stratum::Work *baseWork() { return static_cast<BTC::Stratum::Work*>(Works_[0].Work); }
    FRAC::Stratum::FracWork *fracWork(unsigned index) { return static_cast<FRAC::Stratum::FracWork*>(Works_[index + 1].Work); }

  private:
    BTC::Proto::BlockHeader BaseHeader_;
    BTC::CoinbaseTx BaseLegacy_;
    BTC::CoinbaseTx BaseWitness_;
    std::vector<uint256> BaseMerklePath_;
    BTC::Proto::CheckConsensusCtx BaseConsensusCtx_;

    std::vector<FRAC::Proto::BlockHeader> FRACHeaders_;
    std::vector<BTC::CoinbaseTx> FRACLegacy_;
    std::vector<BTC::CoinbaseTx> FRACWitness_;
    std::vector<uint256> FRACHeaderHashes_;
    std::vector<int> FRACWorkMap_;
    FRAC::Proto::CheckConsensusCtx FRACConsensusCtx_;
  };

  // Build chain-map: same signature as DOGE’s buildChainMap
  static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary, uint32_t &nonce, unsigned &virtualHashesNum);
};
  
} // namespace FRAC
