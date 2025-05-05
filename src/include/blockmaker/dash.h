#include "btc.h"
#include "poolinstances/stratumWorkStorage.h"

namespace DASH {

class Proto {
public:
    static constexpr const char* TickerName = "DASH";

    using BlockHashTy       = BTC::Proto::BlockHashTy;
    using TxHashTy          = BTC::Proto::TxHashTy;
    using AddressTy         = BTC::Proto::AddressTy;
    using BlockHeader       = BTC::Proto::BlockHeader;
    using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
    using ChainParams       = BTC::Proto::ChainParams;
    using Transaction       = BTC::Proto::Transaction;

    static CCheckStatus   checkPow(const BlockHeader& header, uint32_t nBits);
    static void           checkConsensusInitialize(CheckConsensusCtx& ctx) {}
    static CCheckStatus   checkConsensus(const BlockHeader& header, CheckConsensusCtx& ctx, ChainParams& params);
    static double         getDifficulty(const BlockHeader& header);
    static double         expectedWork(const BlockHeader& header, const CheckConsensusCtx& ctx);
    static double         getBlockTime(const BlockHeader& header);
    static void           setBlockTime(BlockHeader& header, uint32_t time);
    static uint32_t       getTime(const BlockHeader& header);
};

class Stratum {
public:
    static constexpr double DifficultyFactor = 1.0;

    using MiningConfig   = BTC::Stratum::MiningConfig;
    using WorkerConfig   = BTC::Stratum::WorkerConfig;
    using StratumMessage = BTC::Stratum::StratumMessage;

    using CSingleWork = StratumSingleWork<
        Proto::BlockHashTy,
        MiningConfig,
        WorkerConfig,
        StratumMessage
    >;
    using CMergedWork = StratumMergedWork<
        Proto::BlockHashTy,
        MiningConfig,
        WorkerConfig,
        StratumMessage
    >;

    using Work       = BTC::WorkTy<
        Proto,
        BTC::Stratum::HeaderBuilder,
        BTC::Stratum::CoinbaseBuilder,
        BTC::Stratum::Notify,
        BTC::Stratum::Prepare,
        MiningConfig,
        WorkerConfig,
        StratumMessage
    >;
    using SecondWork = BTC::Stratum::Work;  // Bitcoin core work

    class MergedWork : public CMergedWork {
    public:
        MergedWork(uint64_t workId,
                   CSingleWork* btcFirst,
                   CSingleWork* dashSecond,
                   MiningConfig& cfg);

        virtual Proto::BlockHashTy shareHash() override {
            return dashWork()->shareHash();
        }

        virtual bool prepareForSubmit(const WorkerConfig& worker,
                                      const StratumMessage& msg) override;

        virtual void buildBlock(size_t idx, xmstream& out) override {
            if (idx == 0)
                btcWork()->buildBlockImpl(btcHeader_, btcLegacy_, btcWitness_, btcMerklePath_, out);
            else
                dashWork()->buildBlockImpl(dashHeader_, dashLegacy_, dashWitness_, dashMerklePath_, out);
        }

        virtual CCheckStatus checkConsensus(size_t idx) override {
            if (idx == 0)
                return BTC::Stratum::Work::checkConsensusImpl(btcHeader_, btcConsensusCtx_);
            return DASH::Proto::checkConsensus(dashHeader_, dashConsensusCtx_, *chainParams_);
        }

    private:
        CSingleWork* btcWork()  { return static_cast<CSingleWork*>(firstWork_); }
        CSingleWork* dashWork() { return static_cast<CSingleWork*>(secondWork_); }

        // Bitcoin context
        BTC::Proto::BlockHeader            btcHeader_;
        BTC::CoinbaseTx                    btcLegacy_;
        BTC::CoinbaseTx                    btcWitness_;
        std::vector<Proto::BlockHashTy>    btcMerklePath_;
        Proto::CheckConsensusCtx           btcConsensusCtx_;

        // Dash context
        Proto::BlockHeader                 dashHeader_;
        BTC::CoinbaseTx                    dashLegacy_;
        BTC::CoinbaseTx                    dashWitness_;
        std::vector<Proto::BlockHashTy>    dashMerklePath_;
        Proto::CheckConsensusCtx           dashConsensusCtx_;

        MiningConfig                       miningCfg_;
        ChainParams*                       chainParams_;
    };

    static constexpr bool MergedMiningSupport = true;
    static bool isMainBackend(const std::string&) { return true; }
    static bool keepOldWorkForBackend(const std::string&) { return false; }

    static void buildSendTargetMessage(xmstream& s, double diff, double factor) {
        BTC::Stratum::buildSendTargetMessageImpl(s, diff, factor);
    }
};

struct X {
    using Proto   = DASH::Proto;
    using Stratum = DASH::Stratum;

    template<typename T>
    static inline void serialize(xmstream& src, const T& data) {
        BTC::Io<T>::serialize(src, data);
    }

    template<typename T>
    static inline void unserialize(xmstream& dst, T& data) {
        BTC::Io<T>::unserialize(dst, data);
    }
};

} // namespace DASH

namespace BTC {
template<> struct Io<DASH::Proto::BlockHeader> {
    static void serialize(xmstream& dst, const DASH::Proto::BlockHeader& data);
    static void unserialize(xmstream& src, DASH::Proto::BlockHeader& data);
};
} // namespace BTC