#pragma once
#include <cstdint>
#include <vector>
#include "btcLike.h"
#include "serialize.h"

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

template <>
void Io<DASH::Proto::Transaction>::serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool serializeWitness = false);

template <>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &src, DASH::Proto::Transaction &data);
