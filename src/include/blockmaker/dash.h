// Copyright (c) 2020 Ivan K.
// Copyright (c) 2020 The BCNode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "btc.h"
#include "poolinstances/stratumWorkStorage.h"

namespace DASH {
  class Proto {
  public:
    static constexpr const char *TickerName = "DASH";

    using BlockHashTy = BTC::Proto::BlockHashTy;
    using TxHashTy    = BTC::Proto::TxHashTy;
    using Transaction = BTC::Proto::Transaction;

    // AuxPoW version bit
    static const int32_t VERSION_AUXPOW = (1 << 8);

    // Extended block header for AuxPoW
    struct BlockHeader : public BTC::Proto::BlockHeader {
      Transaction                  parentCoinbaseTx;
      BlockHashTy                  hashBlock;
      std::vector<BlockHashTy>     merkleBranch;
      int                          index;
      std::vector<BlockHashTy>     chainMerkleBranch;
      int                          chainIndex;
      BTC::Proto::BlockHeader      parentBlock;
    };

    static CCheckStatus checkPow(const BlockHeader &header, uint32_t nBits);
    static CCheckStatus checkConsensus(const BlockHeader &header, CheckConsensusCtx&, ChainParams&);
    static double getDifficulty(const BlockHeader &header);
    static double expectedWork(const BlockHeader &header, const CheckConsensusCtx&);
    static double getBlockTime(const BlockHeader &header);
    static void setBlockTime(BlockHeader &header, uint32_t time);
    static uint32_t getTime(const BlockHeader &header);

    template<typename Stream>
    static void serialize(Stream &s, const BlockHeader &h) {
      // base Bitcoin header
      BTC::Io<BTC::Proto::BlockHeader>::serialize(s, static_cast<const BTC::Proto::BlockHeader&>(h));
      // AuxPoW fields
      BTC::Io<Transaction>::serialize(s, h.parentCoinbaseTx);
      BTC::Io<BlockHashTy>::serialize(s, h.hashBlock);
      BTC::Io<std::vector<BlockHashTy>>::serialize(s, h.merkleBranch);
      s.writeVarInt(h.index);
      BTC::Io<std::vector<BlockHashTy>>::serialize(s, h.chainMerkleBranch);
      s.writeVarInt(h.chainIndex);
      BTC::Io<BTC::Proto::BlockHeader>::serialize(s, h.parentBlock);
    }

    template<typename Stream>
    static void unserialize(Stream &s, BlockHeader &h) {
      BTC::Io<BTC::Proto::BlockHeader>::unserialize(s, static_cast<BTC::Proto::BlockHeader&>(h));
      BTC::Io<Transaction>::unserialize(s, h.parentCoinbaseTx);
      BTC::Io<BlockHashTy>::unserialize(s, h.hashBlock);
      BTC::Io<std::vector<BlockHashTy>>::unserialize(s, h.merkleBranch);
      h.index = s.readVarInt<int>();
      BTC::Io<std::vector<BlockHashTy>>::unserialize(s, h.chainMerkleBranch);
      h.chainIndex = s.readVarInt<int>();
      BTC::Io<BTC::Proto::BlockHeader>::unserialize(s, h.parentBlock);
    }
  };

  class Stratum {
  public:
    static constexpr double DifficultyFactor = 1;

    using MiningConfig   = BTC::Stratum::MiningConfig;
    using WorkerConfig   = BTC::Stratum::WorkerConfig;
    using StratumMessage = BTC::Stratum::StratumMessage;

    using CSingleWork   = StratumSingleWork<BlockHashTy, MiningConfig, WorkerConfig, StratumMessage>;
    using CMergedWork   = StratumMergedWork<BlockHashTy, MiningConfig, WorkerConfig, StratumMessage>;

    using Work         = BTC::WorkTy<DASH::Proto,
                                     BTC::Stratum::HeaderBuilder,
                                     BTC::Stratum::CoinbaseBuilder,
                                     BTC::Stratum::Notify,
                                     BTC::Stratum::Prepare,
                                     MiningConfig,
                                     WorkerConfig,
                                     StratumMessage>;
    using SecondWork   = BTC::Stratum::Work;   // Bitcoin core work
    class MergedWork : public CMergedWork {
    public:
      MergedWork(uint64_t stratumWorkId, CSingleWork *btcWork, CSingleWork *dashWork, MiningConfig &miningCfg);
      virtual Proto::BlockHashTy shareHash() override { return dashWork()->shareHash(); }
      virtual bool prepareForSubmit(const WorkerConfig &workerCfg, const StratumMessage &msg) override;
      virtual void buildBlock(size_t workIdx, xmstream &blockHexData) override {
        if (workIdx == 0) {
          btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
        } else {
          dashWork()->buildBlockImpl(DASHHeader_, DASHWitness_, blockHexData);
        }
      }
      virtual CCheckStatus checkConsensus(size_t workIdx) override {
        if (workIdx == 0)
          return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, DASHConsensusCtx_);
        else
          return DASH::Proto::checkConsensus(DASHHeader_, DASHConsensusCtx_, *chainParams_);
      }
    private:
      CSingleWork* btcWork()   { return static_cast<CSingleWork*>(firstWork_); }
      CSingleWork* dashWork()  { return static_cast<CSingleWork*>(secondWork_); }
      BTC::Proto::BlockHeader BTCHeader_;
      xmstream               BTCWitness_;
      CheckConsensusCtx      BTCConsensusCtx_;
      BlockHeader            DASHHeader_;
      xmstream               DASHWitness_;
      CheckConsensusCtx      DASHConsensusCtx_;
      MiningConfig           miningCfg_;
      ChainParams*           chainParams_;
    };

    static constexpr bool MergedMiningSupport = true;

    static bool isMainBackend(const std::string&) { return true; }
    static bool keepOldWorkForBackend(const std::string&) { return false; }

    static void buildSendTargetMessage(xmstream &stream, double difficulty, double DifficultyFactor) {
      BTC::Stratum::buildSendTargetMessageImpl(stream, difficulty, DifficultyFactor);
    }
  };

  struct X {
    using Proto = DASH::Proto;
    using Stratum = DASH::Stratum;
    template<typename T> static inline void serialize(xmstream &src, const T &data) { BTC::Io<T>::serialize(src, data); }
    template<typename T> static inline void unserialize(xmstream &dst, T &data) { BTC::Io<T>::unserialize(dst, data); }
  };
}
