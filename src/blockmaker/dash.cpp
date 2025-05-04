// dash.cpp
#include "blockmaker/dash.h"
#include "blockmaker/serialize.h"

namespace BTC {

template <>
void Io<DASH::Proto::Transaction>::serialize(xmstream &stream, const DASH::Proto::Transaction &tx) {
  serialize(stream, tx.version);
  serialize(stream, tx.type);
  serialize(stream, tx.vin);
  serialize(stream, tx.vout);
  serialize(stream, tx.lockTime);
  serialize(stream, tx.extraPayload);
}

template <>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &stream, DASH::Proto::Transaction &tx) {
  unserialize(stream, tx.version);
  unserialize(stream, tx.type);
  unserialize(stream, tx.vin);
  unserialize(stream, tx.vout);
  unserialize(stream, tx.lockTime);
  unserialize(stream, tx.extraPayload);
}

} // namespace BTC
