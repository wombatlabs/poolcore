#include "blockmaker/dash.h"
#include "blockmaker/serialize.h"
#include "p2putils/xmstream.h"

namespace BTC {

template<>
void Io<DASH::Proto::Transaction>::serialize(xmstream &stream, const DASH::Proto::Transaction &tx) {
  stream.write<int32_t>(tx.version);
  IoArray<DASH::Proto::TxIn>::serialize(stream, tx.vin);
  IoArray<DASH::Proto::TxOut>::serialize(stream, tx.vout);
  stream.write<uint32_t>(tx.lockTime);

  if (!tx.vExtraPayload.empty()) {
    serializeVarSize(stream, tx.vExtraPayload.size());
    stream.write(tx.vExtraPayload.data(), tx.vExtraPayload.size());
  }
}

template<>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &stream, DASH::Proto::Transaction &tx) {
  tx.version = stream.read<int32_t>();
  IoArray<DASH::Proto::TxIn>::unserialize(stream, tx.vin);
  IoArray<DASH::Proto::TxOut>::unserialize(stream, tx.vout);
  tx.lockTime = stream.read<uint32_t>();

  if (stream.remaining() > 0) {
    size_t payloadSize = unserializeVarSize(stream);
    tx.vExtraPayload.resize(payloadSize);
    stream.read(tx.vExtraPayload.data(), payloadSize);
  }
}

} // namespace BTC
