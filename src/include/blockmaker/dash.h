// dependencies/poolcore/src/include/blockmaker/dash.h
#pragma once

#include "btc.h"                   // pulls in BTC::Proto, BTC::WorkTy, etc.
#include "blockmaker/stratumWork.h"// for StratumSingleWorkEmpty, StratumMergedWorkEmpty

namespace DASH {

class Proto {
public:
    static constexpr const char* TickerName = "DASH";

    using BlockHashTy = BTC::Proto::BlockHashTy;
    using TxHashTy    = BTC::Proto::TxHashTy;
    using AddressTy   = BTC::Proto::AddressTy;

    // AuxPoW version bit
    static const int32_t VERSION_AUXPOW = (1 << 8);

    // Extended header: base BTC + AuxPoW fields
    struct BlockHeader : public BTC::Proto::BlockHeader {
        BTC::Proto::Transaction         parentCoinbaseTx;
        BlockHashTy                     hashBlock;
        std::vector<BlockHashTy>        merkleBranch;
        uint32_t                        index;
        std::vector<BlockHashTy>        chainMerkleBranch;
        uint32_t                        chainIndex;
        BTC::Proto::BlockHeader         parentBlock;
    };

    static CCheckStatus checkPow(const BlockHeader& header, uint32_t nBits);
    static void          checkConsensusInitialize(BTC::Proto::CheckConsensusCtx& ctx) { /* nop */ }
    static CCheckStatus  checkConsensus(const BlockHeader& header,
                                        BTC::Proto::CheckConsensusCtx& ctx,
                                        BTC::Proto::ChainParams& params);
    static double        expectedWork(const BlockHeader& header,
                                      const BTC::Proto::CheckConsensusCtx& ctx);
    static double        getDifficulty(const BlockHeader& header);
    static uint32_t      getTime(const BlockHeader& header);
    static void          setTime(BlockHeader& header, uint32_t t);
};

class Stratum {
public:
    static constexpr double DifficultyFactor = 1.0;

    using MiningConfig   = BTC::CMiningConfig;
    using WorkerConfig   = BTC::CWorkerConfig;
    using StratumMessage = BTC::CStratumMessage;

    // Base classes for work units
    using CSingleWork = StratumSingleWorkEmpty<
        Proto::BlockHashTy,
        MiningConfig,
        WorkerConfig,
        StratumMessage
    >;
    using CMergedWork = StratumMergedWorkEmpty<
        Proto::BlockHashTy,
        MiningConfig,
        WorkerConfig,
        StratumMessage
    >;

    // Primary “real” work generator
    using Work = BTC::WorkTy<
        Proto,
        BTC::Stratum::HeaderBuilder,
        BTC::Stratum::CoinbaseBuilder,
        BTC::Stratum::Notify,
        BTC::Stratum::Prepare
    >;

    // For merged mining
    using SecondWork = BTC::Stratum::Work;  // Bitcoin
    class MergedWork : public CMergedWork {
    public:
        MergedWork(uint64_t workId,
                   CSingleWork* first,
                   CSingleWork* second,
                   MiningConfig& cfg);
        virtual bool prepareForSubmit(const WorkerConfig& worker,
                                      const StratumMessage& msg) override;
        virtual Proto::BlockHashTy shareHash() override {
            return dashWork()->shareHash();
        }
        // optionally override buildBlock/checkConsensus if needed…

    private:
        CSingleWork* btcWork()  { return static_cast<CSingleWork*>(firstWork_);  }
        CSingleWork* dashWork() { return static_cast<CSingleWork*>(secondWork_); }

        // you’ll use these members in your .cpp
    };

    static constexpr bool MergedMiningSupport = true;

    static void buildSendTargetMessage(xmstream& s,
                                       double difficulty,
                                       double factor) {
        BTC::Stratum::buildSendTargetMessageImpl(s, difficulty, factor);
    }

    // hook called by StratumInstance to initialize config from JSON
    static void miningConfigInitialize(MiningConfig& cfg,
                                       const rapidjson::Value& v) {
        BTC::Stratum::miningConfigInitialize(cfg, v);
    }

    // hook to turn a string+prefix into AddressTy
    static bool decodeHumanReadableAddress(const std::string& str,
                                           uint8_t prefix,
                                           AddressTy& out) {
        return BTC::Proto::decodeHumanReadableAddress(str, prefix, out);
    }
};

} // namespace DASH
