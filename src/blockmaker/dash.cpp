#include "blockmaker/dash.h"
#include "blockmaker/serialize.h"
#include "p2putils/xmstream.h"

using namespace DASH;

namespace BTC {

template<>
void Io<Proto::Transaction>::serialize(xmstream &stream, const Proto::Transaction &tx) {
    stream.write<int32_t>(tx.version);
    BTC::IoArray<Proto::TxIn>::serialize(stream, tx.vin);
    BTC::IoArray<Proto::TxOut>::serialize(stream, tx.vout);
    stream.write<uint32_t>(tx.lockTime);

    if (!tx.vExtraPayload.empty()) {
        serializeVarSize(stream, tx.vExtraPayload.size());
        stream.write(tx.vExtraPayload.data(), tx.vExtraPayload.size());
    }
}

template<>
void Io<Proto::Transaction>::unserialize(xmstream &stream, Proto::Transaction &tx) {
    tx.version = stream.read<int32_t>();
    BTC::IoArray<Proto::TxIn>::unserialize(stream, tx.vin);
    BTC::IoArray<Proto::TxOut>::unserialize(stream, tx.vout);
    tx.lockTime = stream.read<uint32_t>();

    if (stream.remaining() > 0) {
        uint64_t payloadSize;
        BTC::unserializeVarSize(stream, payloadSize);
        tx.vExtraPayload.resize(payloadSize);
        stream.read(tx.vExtraPayload.data(), payloadSize);
    }
}

} // namespace BTC
