#include "btc.h"
#include "serialize.h"
#include "blockmaker/x11.h"

namespace DASH {
namespace Proto {

// Dash ticker
static constexpr const char *TickerName = "DASH";

// Reuse Bitcoin types
using BlockHashTy = BTC::Proto::BlockHashTy;
using TxHashTy    = BTC::Proto::TxHashTy;
using AddressTy   = BTC::Proto::AddressTy;
using BlockHeader = BTC::Proto::BlockHeader;
using TxIn        = BTC::Proto::TxIn;
using TxOut       = BTC::Proto::TxOut;

// Dash transaction with extra payload
struct Transaction {
    int32_t               version;
    xvector<TxIn>         txIn;
    xvector<TxOut>        txOut;
    uint32_t              lockTime;
    xvector<uint8_t>      vExtraPayload;  // only for special TX types

    // Memory-only cache fields
    uint32_t              SerializedDataOffset = 0;
    uint32_t              SerializedDataSize   = 0;
    TxHashTy              Hash;

    bool hasWitness() const { return false; }
};

// Dash-specific proof-of-work (X11)
CCheckStatus checkPow(const BlockHeader &header, uint32_t nBits);

} // namespace Proto
} // namespace DASH

// Serialization specialization for DASH::Proto::Transaction
namespace BTC {
template<> struct Io<DASH::Proto::Transaction> {
    static void serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool serializeWitness = false);
    static void unserialize(xmstream &src, DASH::Proto::Transaction &data);
    static void unpack(xmstream &src, DynamicPtr<DASH::Proto::Transaction> dst) { unserialize(src, *dst.ptr()); }
    static void unpackFinalize(DynamicPtr<DASH::Proto::Transaction> dst) {}
};
} // namespace BTC

// Stratum handler for Dash (X11)
namespace DASH {
class Stratum {
public:
    static constexpr double DifficultyFactor = 1.0;

    using Work = BTC::WorkTy<DASH::Proto, BTC::Stratum::HeaderBuilder, BTC::Stratum::CoinbaseBuilder, BTC::Stratum::Notify, BTC::Stratum::Prepare>;
    static constexpr bool MergedMiningSupport = false;

    static Work* newPrimaryWork(int64_t stratumId,
                                PoolBackend *backend,
                                size_t backendIdx,
                                const CMiningConfig &miningCfg,
                                const std::vector<uint8_t> &miningAddress,
                                const std::string &coinbaseMessage,
                                CBlockTemplate &blockTemplate,
                                std::string &error) {
        return BTC::Stratum::newPrimaryWork(stratumId, backend, backendIdx,
                                            miningCfg, miningAddress, coinbaseMessage,
                                            blockTemplate, error);
    }

    static StratumSingleWork* newSecondaryWork(int64_t,
                                               PoolBackend*,
                                               size_t,
                                               const CMiningConfig&,
                                               const std::vector<uint8_t>&,
                                               const std::string&,
                                               CBlockTemplate&,
                                               const std::string&) {
        return nullptr;
    }

    static StratumMergedWork* newMergedWork(int64_t,
                                            std::vector<StratumSingleWork*>&,
                                            const CMiningConfig&,
                                            const std::string&) {
        return nullptr;
    }

    static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg, const char *in, size_t size) {
        return BTC::Stratum::decodeStratumMessage(msg, in, size);
    }

    static void miningConfigInitialize(CMiningConfig &miningCfg, rapidjson::Value &instanceCfg) {
        BTC::Stratum::miningConfigInitialize(miningCfg, instanceCfg);
    }

    static void workerConfigInitialize(CWorkerConfig &workerCfg, ThreadConfig &threadCfg) {
        BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg);
    }

    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
        BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
    }

    static void workerConfigOnSubscribe(CWorkerConfig &workerCfg,
                                        const CMiningConfig &miningCfg,
                                        CStratumMessage &msg,
                                        xmstream &out,
                                        std::string &subscribeInfo) {
        BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo);
    }

    static void buildSendTargetMessage(xmstream &stream, double difficulty) {
        BTC::Stratum::buildSendTargetMessage(stream, difficulty, DifficultyFactor);
    }
};

// Coin descriptor for pool instances
struct X {
    using Proto   = DASH::Proto;
    using Stratum = DASH::Stratum;

    template<typename T>
    static inline void serialize(xmstream &dst, const T &data) { Io<T>::serialize(dst, data); }

    template<typename T>
    static inline void unserialize(xmstream &src, T &data) { Io<T>::unserialize(src, data); }
};

} // namespace DASH