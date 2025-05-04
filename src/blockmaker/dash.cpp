#include "blockmaker/dash.h"
#include "serialize.h"

namespace BTC {
template<>
void Io<DASH::Proto::Transaction>::serialize(xmstream &stream, const DASH::Proto::Transaction &tx) {
  stream.write<uint32_t>(tx.version);
  IoArray<DASH::Proto::TxIn>::serialize(stream, tx.vin);
  IoArray<DASH::Proto::TxOut>::serialize(stream, tx.vout);
  stream.write<uint32_t>(tx.lockTime);

  // Dash's vExtraPayload
  if (!tx.vExtraPayload.empty()) {
    serializeVarint(stream, tx.vExtraPayload.size());
    stream.write(tx.vExtraPayload.data(), tx.vExtraPayload.size());
  }
}

template<>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &stream, DASH::Proto::Transaction &tx) {
  tx.version = stream.read<uint32_t>();
  IoArray<DASH::Proto::TxIn>::unserialize(stream, tx.vin);
  IoArray<DASH::Proto::TxOut>::unserialize(stream, tx.vout);
  tx.lockTime = stream.read<uint32_t>();

  // Try reading Dash's vExtraPayload if remaining
  if (!stream.isEmpty()) {
    size_t size = readVarint(stream);
    tx.vExtraPayload.resize(size);
    stream.read(tx.vExtraPayload.data(), size);
  }
}
} // namespace BTC