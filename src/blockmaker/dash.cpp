#include "blockmaker/dash.h"

template <>
void Io<DASH::Proto::Transaction>::serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool /*serializeWitness*/) {
    dst.write<uint32_t>(data.version);
    IoArray<TxIn>::serialize(dst, data.vin);
    IoArray<TxOut>::serialize(dst, data.vout);
    dst.write<uint32_t>(data.lockTime);

    if (data.hasExtraPayload()) {
        dst.writeVarint(data.vExtraPayload.size());
        dst.write(data.vExtraPayload.data(), data.vExtraPayload.size());
    }
}

template <>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &src, DASH::Proto::Transaction &data) {
    data.version = src.read<uint32_t>();
    IoArray<TxIn>::unserialize(src, data.vin);
    IoArray<TxOut>::unserialize(src, data.vout);
    data.lockTime = src.read<uint32_t>();

    if (!src.empty()) {
        size_t payloadSize = src.readVarint();
        data.vExtraPayload.resize(payloadSize);
        src.read(data.vExtraPayload.data(), payloadSize);
    }
}
