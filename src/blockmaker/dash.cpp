#include "blockmaker/dash.h"
#include "blockmaker/serialize.h"
#include "p2putils/xmstream.h"

using namespace DASH;

namespace BTC {

template<>
struct Io<DASH::Proto::Transaction> {
  static void serialize(xmstream &stream, const DASH::Proto::Transaction &tx, bool /*serializeWitness*/) {
    stream.write<int32_t>(tx.version);
    BTC::IoArray<DASH::Proto::TxIn>::serialize(stream, tx.vin);
    BTC::IoArray<DASH::Proto::TxOut>::serialize(stream, tx.vout);
    stream.write<uint32_t>(tx.lockTime);

    if (!tx.vExtraPayload.empty()) {
      serializeVarSize(stream, tx.vExtraPayload.size());
      stream.write(tx.vExtraPayload.data(), tx.vExtraPayload.size());
    }
  }

  static void unserialize(xmstream &stream, DASH::Proto::Transaction &tx) {
    tx.version = stream.read<int32_t>();
    BTC::IoArray<DASH::Proto::TxIn>::unserialize(stream, tx.vin);
    BTC::IoArray<DASH::Proto::TxOut>::unserialize(stream, tx.vout);
    tx.lockTime = stream.read<uint32_t>();

    if (stream.remaining() > 0) {
      uint64_t payloadSize;
      unserializeVarSize(stream, payloadSize);
      tx.vExtraPayload.resize(payloadSize);
      stream.read(tx.vExtraPayload.data(), payloadSize);
    }
  }
};

} // namespace BTC
