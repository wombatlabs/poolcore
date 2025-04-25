#include "blockmaker/dash.h"
#include "blockmaker/serialize.h"

namespace BTC {

template <>
void Io<DASH::Proto::Transaction>::serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool /*serializeWitness*/) {
    BTC::serialize(dst, data.version);
    BTC::serialize(dst, data.vin);
    BTC::serialize(dst, data.vout);
    BTC::serialize(dst, data.lockTime);

    if (!data.vExtraPayload.empty()) {
        BTC::serializeVarSize(dst, data.vExtraPayload.size());
        dst.write(data.vExtraPayload.data(), data.vExtraPayload.size());
    }
}

template <>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &src, DASH::Proto::Transaction &data) {
    BTC::unserialize(src, data.version);
    BTC::unserialize(src, data.vin);
    BTC::unserialize(src, data.vout);
    BTC::unserialize(src, data.lockTime);

    if (src.remaining()) {
        uint64_t payloadSize;
        BTC::unserializeVarSize(src, payloadSize);
        data.vExtraPayload.resize(payloadSize);
        src.read(data.vExtraPayload.data(), payloadSize);
    }
}

} // namespace BTC
