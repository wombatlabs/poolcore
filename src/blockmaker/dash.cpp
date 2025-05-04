#include "blockmaker/dash.h"
#include "blockmaker/x11.h"

template <>
void Io<DASH::Proto::Transaction>::serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool /*serializeWitness*/) {
    dst.write<int32_t>(data.nVersion);
    write_array(dst, data.vin);
    write_array(dst, data.vout);
    dst.write<uint32_t>(data.nLockTime);
    dst.write_varint(data.vExtraPayload.size());
    dst.write(data.vExtraPayload.data(), data.vExtraPayload.size());
}

template <>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &src, DASH::Proto::Transaction &data) {
    data.nVersion = src.read<int32_t>();
    read_array(src, data.vin);
    read_array(src, data.vout);
    data.nLockTime = src.read<uint32_t>();
    size_t extraPayloadSize = src.read_varint();
    data.vExtraPayload.resize(extraPayloadSize);
    src.read(data.vExtraPayload.data(), extraPayloadSize);
}

uint256 getPoWHash(const DASH::Proto::BlockHeader &header) {
    return getPoWHashX11((const uint8_t *)&header, sizeof(header));
}
