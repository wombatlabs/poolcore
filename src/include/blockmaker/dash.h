#pragma once
#include <cstdint>
#include <vector>

#include "blockmaker/btc.h"
#include "serialize.h"
#include "p2putils/xmstream.h"

namespace DASH {
namespace Proto {

struct Transaction {
    int32_t version;
    std::vector<BTC::Proto::TxIn> vin;
    std::vector<BTC::Proto::TxOut> vout;
    uint32_t lockTime;
    std::vector<uint8_t> vExtraPayload;

    bool hasExtraPayload() const {
        return !vExtraPayload.empty();
    }
};

// Required by StratumInstance
using AddressTy = std::vector<uint8_t>;

static inline bool decodeHumanReadableAddress(const std::string &addr, const std::vector<uint8_t> &prefix, AddressTy &decoded) {
    return BTC::Proto::decodeHumanReadableAddress(addr, prefix, decoded); // Use BTC logic
}

} // namespace Proto
} // namespace DASH

namespace DASH {

// Required traits for stratum instance
struct StratumTraits {
    static constexpr bool MergedMiningSupport = false;

    static void miningConfigInitialize(CMiningConfig &cfg, rapidjson::Value &json) {
        BTC::Stratum::miningConfigInitialize(cfg, json); // Reuse BTC
    }
};

// Declare Stratum type using BTC-like logic
using Stratum = WorkTy<
    DASH::Proto,
    BTC::Stratum::HeaderBuilder,
    BTC::Stratum::CoinbaseBuilder,
    BTC::Stratum::Notify,
    BTC::Stratum::Prepare,
    StratumTraits
>;

// Required factory function
static Stratum::Work *newPrimaryWork(int64_t stratumId,
                                     CBlockTemplate &blockTemplate,
                                     const CMiningConfig &miningCfg,
                                     PoolBackend *backend,
                                     size_t backendId,
                                     std::string &error) {
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "invalid work type";
        return nullptr;
    }

    std::unique_ptr<Stratum::Work> work(new Stratum::Work(stratumId,
                                                          blockTemplate.UniqueWorkId,
                                                          backend,
                                                          backendId,
                                                          miningCfg));

    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

// Namespace required by StratumInstance
struct X {
    using Proto = DASH::Proto;
    using Stratum = DASH::Stratum;

    template<typename T>
    static inline void serialize(xmstream &src, const T &data) {
        BTC::Io<T>::serialize(src, data); // Use BTC's template implementation
    }

    template<typename T>
    static inline void unserialize(xmstream &dst, T &data) {
        BTC::Io<T>::unserialize(dst, data); // Use BTC's template implementation
    }
};

} // namespace DASH
