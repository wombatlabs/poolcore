#pragma once
#include <cstdint>
#include <vector>
#include <string>

#include "blockmaker/stratumWork.h"  // For WorkTy
#include "blockmaker/btc.h"          // For BTC::Proto types
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

// ✅ Match BTC's address type to satisfy StratumInstance<X>
using AddressTy = BTC::Proto::AddressTy;

static inline bool decodeHumanReadableAddress(const std::string &addr,
                                              const std::vector<uint8_t> &prefix,
                                              AddressTy &decoded) {
    return BTC::Proto::decodeHumanReadableAddress(addr, prefix, decoded);
}

} // namespace Proto
} // namespace DASH

namespace DASH {

// ✅ Traits for poolcore stratum engine
struct StratumTraits {
    static constexpr bool MergedMiningSupport = false;

    static void miningConfigInitialize(CMiningConfig &cfg, rapidjson::Value &json) {
        BTC::Stratum::miningConfigInitialize(cfg, json); // Reuse BTC logic
    }
};

// ✅ Dash-specific Work type (uses Bitcoin-like structure)
using Stratum = WorkTy<
    DASH::Proto,
    BTC::Stratum::HeaderBuilder,
    BTC::Stratum::CoinbaseBuilder,
    BTC::Stratum::Notify,
    BTC::Stratum::Prepare,
    StratumTraits
>;

// ✅ Used by Fabric to instantiate Dash jobs
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

// ✅ Plug-in class for StratumInstance<X>
struct X {
    using Proto = DASH::Proto;
    using Stratum = DASH::Stratum;

    template<typename T>
    static inline void serialize(xmstream &src, const T &data) {
        BTC::Io<T>::serialize(src, data);
    }

    template<typename T>
    static inline void unserialize(xmstream &dst, T &data) {
        BTC::Io<T>::unserialize(dst, data);
    }
};

} // namespace DASH
