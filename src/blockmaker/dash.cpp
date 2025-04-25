#include "blockmaker/dash.h"
#include "blockmaker/serialize.h"
#include "blockmaker/serializeUtils.h"

template <>
struct Io<DASH::Proto::Transaction> {
    static void serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool /*serializeWitness*/) {
        dst.write<uint32_t>(data.version);
        IoArray<BTC::Proto::TxIn>::serialize(dst, data.vin);
        IoArray<BTC::Proto::TxOut>::serialize(dst, data.vout);
        dst.write<uint32_t>(data.lockTime);

        if (data.hasExtraPayload()) {
            dst.writeVarint(data.vExtraPayload.size());
            dst.write(data.vExtraPayload.data(), data.vExtraPayload.size());
        }
    }

    static void unserialize(xmstream &src, DASH::Proto::Transaction &data) {
        data.version = src.read<uint32_t>();
        IoArray<BTC::Proto::TxIn>::unserialize(src, data.vin);
        IoArray<BTC::Proto::TxOut>::unserialize(src, data.vout);
        data.lockTime = src.read<uint32_t>();

        if (!src.empty()) {
            size_t payloadSize = src.readVarint();
            data.vExtraPayload.resize(payloadSize);
            src.read(data.vExtraPayload.data(), payloadSize);
        }
    }
};

