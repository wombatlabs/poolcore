#pragma once
#include <cstdint>
#include <vector>

#include "btc.h"
#include "serialize.h"

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

} // namespace Proto
} // namespace DASH

namespace DASH {

using Stratum = WorkTy<
    DASH::Proto,
    BTC::Stratum::HeaderBuilder,
    BTC::Stratum::CoinbaseBuilder,
    BTC::Stratum::Notify,
    BTC::Stratum::Prepare
>;

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

struct X {
  using Proto = DASH::Proto;
  using Stratum = DASH::Stratum;

  template<typename T> static inline void serialize(xmstream &src, const T &data) { Io<T>::serialize(src, data); }
  template<typename T> static inline void unserialize(xmstream &dst, T &data) { Io<T>::unserialize(dst, data); }
};

} // namespace DASH
