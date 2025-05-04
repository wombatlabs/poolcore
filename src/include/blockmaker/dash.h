#pragma once
#include <cstdint>
#include <vector>
#include <string>

#include "btc.h"
#include "stratumWork.h"
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

// ✅ Must match BTC address type
using AddressTy = BTC::Proto::AddressTy;

static inline bool decodeHumanReadableAddress(const std::string &addr,
                                              const std::vector<uint8_t> &prefix,
                                              AddressTy &decoded) {
    return BTC::Proto::decodeHumanReadableAddress(addr, prefix, decoded);
}

} // namespace Proto

// ✅ Dash-specific stratum traits
struct StratumTraits {
    static constexpr bool MergedMiningSupport = false;

    static void miningConfigInitialize(CMiningConfig &cfg, rapidjson::Value &json) {
        BTC::Stratum::miningConfigInitialize(cfg, json);
    }
};

// ✅ Work type for Dash using BTC logic
using Stratum = WorkTy<
    Proto,
    BTC::Stratum::HeaderBuilder,
    BTC::Stratum::CoinbaseBuilder,
    BTC::Stratum::Notify,
    BTC::Stratum::Prepare,
    StratumTraits
>;

// ✅ Factory function
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

// ✅ Adapter for StratumInstance<X>
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
