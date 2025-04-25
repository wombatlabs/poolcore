#include "blockmaker/dash.h"
#include "blockmaker/serialize.h"

namespace BTC { // This is where Io is defined

template <>
void Io<DASH::Proto::Transaction>::serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool /*serializeWitness*/) {
    serialize(dst, data.version);
    IoArray<Proto::TxIn>::serialize(dst, data.vin);
    IoArray<Proto::TxOut>::serialize(dst, data.vout);
    serialize(dst, data.lockTime);

    if (!data.vExtraPayload.empty()) {
        dst.writeVarint(data.vExtraPayload.size());
        dst.write(data.vExtraPayload.data(), data.vExtraPayload.size());
    }
}

template <>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &src, DASH::Proto::Transaction &data) {
    unserialize(src, data.version);
    IoArray<Proto::TxIn>::unserialize(src, data.vin);
    IoArray<Proto::TxOut>::unserialize(src, data.vout);
    unserialize(src, data.lockTime);

    if (!src.isEmpty()) {
        size_t payloadSize = src.readVarint();
        data.vExtraPayload.resize(payloadSize);
        src.read(data.vExtraPayload.data(), payloadSize);
    }
}

} // namespace BTC
