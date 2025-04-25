#pragma once
#include <cstdint>
#include <vector>
#include "btcLike.h"
#include "serialize.h"
#include "btc.h"

namespace DASH {
namespace Proto {

struct Transaction {
    int32_t version;
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    uint32_t lockTime;
    std::vector<uint8_t> vExtraPayload;

    bool hasExtraPayload() const {
        return !vExtraPayload.empty();
    }
};

} // namespace Proto
} // namespace DASH

